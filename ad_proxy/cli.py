"""
Active Directory LDAPS Proxy CLI.
Administrative and operational utility for starting the proxy, validating YAML configuration,
verifying Domain Controller LDAPS connectivity, simulating AI agent requests, and listing commands.
"""

import argparse
import base64
import json
import logging
import os
import sys
from typing import Any, Dict
from .commands import registry
from .models import ProxyConfig, ProxyRequest
from .proxy_engine import AdProxyEngine
from .server import AdProxyServer
from .yaml_loader import build_proxy_config, load_yaml_raw

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ad_proxy.cli")


def parse_cli_params(param_list: list) -> Dict[str, Any]:
    """Parses key=value arguments from CLI into typed Python primitives."""
    params: Dict[str, Any] = {}
    if not param_list:
        return params
    for p in param_list:
        if "=" in p:
            k, v = p.split("=", 1)
            if v.lower() == "true":
                params[k] = True
            elif v.lower() == "false":
                params[k] = False
            elif v.isdigit():
                params[k] = int(v)
            else:
                params[k] = v
        else:
            params[p] = True
    return params


def serialize_config_summary(config: ProxyConfig, config_path: str) -> Dict[str, Any]:
    """Serializes the active ProxyConfig into a structured dictionary for UI and CLI inspection."""
    accounts = []
    for acc in config.allowed_service_accounts.values():
        rules = [
            {
                "command": r.command,
                "allowed_groups": r.allowed_groups or [],
                "restricted_groups": r.restricted_groups or [],
                "allowed_ous": r.allowed_ous or [],
                "allowed_attributes": r.allowed_attributes or [],
                "max_search_results": r.max_search_results,
                "require_approval_ticket": r.require_approval_ticket,
            }
            for r in acc.rules
        ]
        accounts.append({
            "account_identifier": acc.account_identifier,
            "description": acc.description,
            "permitted_commands": acc.permitted_commands,
            "denied_commands": acc.denied_commands,
            "rules": rules,
        })

    return {
        "config_path": config_path,
        "domain_name": config.active_directory.domain_name,
        "base_dn": config.active_directory.base_dn,
        "domain_controllers": config.active_directory.domain_controllers,
        "ldaps_port": config.active_directory.ldaps_port,
        "tls_min_version": config.ldaps.min_version,
        "auth_mode": config.upstream_auth.mode.value,
        "secret_provider": config.upstream_auth.secret_provider.value,
        "gmsa_name": config.upstream_auth.gmsa_name,
        "siem_enabled": config.siem.enabled,
        "siem_format": config.siem.format.value,
        "siem_destinations": config.siem.destinations,
        "listen_host": config.listen_host,
        "listen_port": config.listen_port,
        "service_accounts": accounts,
    }


def format_check_output(config: ProxyConfig, config_path: str) -> str:
    """Builds a human-readable validation report for the parsed configuration."""
    lines = [
        f"[OK] Configuration successfully parsed from: {config_path}",
        f"  - Active Directory Domain:   {config.active_directory.domain_name}",
        f"  - Base DN:                   {config.active_directory.base_dn}",
        f"  - Domain Controllers:        {', '.join(config.active_directory.domain_controllers)}",
        f"  - Upstream Auth Mode:        {config.upstream_auth.mode.value}",
        f"  - Secret Provider:           {config.upstream_auth.secret_provider.value}",
        f"  - SIEM Format:               {config.siem.format.value}",
        f"  - SIEM Destinations:         {', '.join(config.siem.destinations)}",
        f"  - Registered Service Accounts: {len(config.allowed_service_accounts)}",
    ]
    for acc in config.allowed_service_accounts.values():
        lines.append(
            f"     * {acc.account_identifier} ({acc.description}) -> Permitted: {len(acc.permitted_commands)} commands"
        )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Active Directory LDAPS Proxy for AI Agents & Service Accounts"
    )
    parser.add_argument(
        "--config",
        "-c",
        default="ad_proxy/config.yaml",
        help="Path to YAML configuration file (default: ad_proxy/config.yaml)",
    )
    parser.add_argument("--run", action="store_true", help="Start the AD-Proxy LDAPS service")
    parser.add_argument("--tls", dest="use_tls", action="store_true", default=True, help="Enable TLS 1.2+ encryption on listener (default: enabled)")
    parser.add_argument("--no-tls", dest="use_tls", action="store_false", help="Disable TLS on listener (development only)")
    parser.add_argument("--check-config", action="store_true", help="Validate YAML schema and secret settings")
    parser.add_argument("--dump-config-json", action="store_true", help="Output parsed configuration and validation summary as JSON")
    parser.add_argument("--execute-json", help="Execute a base64-encoded JSON ProxyRequest and output JSON result")
    parser.add_argument("--test-dc", action="store_true", help="Test LDAPS connectivity to Domain Controllers")
    parser.add_argument("--list-commands", action="store_true", help="List all permissible Active Directory commands")
    parser.add_argument("--run-tests", action="store_true", help="Execute built-in unit & security test suite")

    # Simulation options
    parser.add_argument("--simulate-agent", action="store_true", help="Simulate an AI agent LDAPS query")
    parser.add_argument("--agent", help="Service account identifier (e.g. ai-triage-agent)")
    parser.add_argument("--password", help="Service account password for AD authentication")
    parser.add_argument("--command", help="AD command to execute (e.g. list_group_members)")
    parser.add_argument("--param", action="append", help="Command parameters as key=value (e.g. --param group_name=VPN-Users)")
    parser.add_argument("--ticket-id", help="IT approval or change ticket ID (e.g. CHG-2026-994)")

    args = parser.parse_args()

    # List commands
    if args.list_commands:
        print("\n================ ACTIVE DIRECTORY LDAPS COMMAND CATALOG ================\n")
        for cmd in registry.list_commands():
            print(f"Command:     {cmd['name']}")
            print(f"Category:    {cmd['category']} | Risk Level: {cmd['risk_level']}")
            print(f"Description: {cmd['description']}")
            print(f"Required:    {', '.join(cmd['required_params']) or 'None'}")
            print(f"Optional:    {', '.join(cmd['optional_params']) or 'None'}")
            print("-" * 72)
        return

    # Run internal test suite
    if args.run_tests:
        from tests.test_proxy import run_all_tests
        success = run_all_tests()
        sys.exit(0 if success else 1)

    # Load configuration
    config_path = args.config
    if not os.path.exists(config_path):
        fallback = os.path.join(os.path.dirname(__file__), "config.yaml")
        if os.path.exists(fallback):
            config_path = fallback
        else:
            print(f"Error: Configuration file not found at '{args.config}'", file=sys.stderr)
            sys.exit(1)

    raw_dict = load_yaml_raw(config_path)
    config = build_proxy_config(raw_dict)
    engine = AdProxyEngine(config)

    # Check config (human-readable)
    if args.check_config:
        print(format_check_output(config, config_path))
        return

    # Dump config (structured JSON for Web Console)
    if args.dump_config_json:
        output = {
            "summary": serialize_config_summary(config, config_path),
            "check_output": format_check_output(config, config_path),
        }
        print(json.dumps(output))
        return

    # Execute JSON payload (used by Web Console API)
    if args.execute_json:
        input_data = json.loads(base64.b64decode(args.execute_json).decode("utf-8"))
        req = ProxyRequest(
            caller_account=input_data["caller_account"],
            caller_password=input_data["caller_password"],
            command=input_data["command"],
            parameters=input_data.get("parameters", {}),
            client_ip=input_data.get("client_ip", "127.0.0.1"),
            ticket_id=input_data.get("ticket_id"),
        )
        res = engine.process_request(req)
        recent = engine.siem.get_recent_events(limit=1)
        siem_event = recent[0] if recent else None
        print(json.dumps({
            "success": res.success,
            "status_code": res.status_code,
            "message": res.message,
            "data": res.data,
            "request_id": res.request_id,
            "duration_ms": res.duration_ms,
            "siem_event": siem_event,
        }))
        return

    # Test DC connectivity
    if args.test_dc:
        print(f"Testing LDAPS connection to Domain Controllers: {config.active_directory.domain_controllers}...")
        root_dse = engine.ldap_client.get_root_dse()
        print("[OK] Domain Controller responded via LDAPS successfully.")
        print(json.dumps(root_dse, indent=2))
        return

    # Simulate AI agent query
    if args.simulate_agent:
        agent = args.agent or "ai-triage-agent"
        pwd = args.password or "AgentSecurePassword2026!"
        cmd = args.command or "list_group_members"
        params = parse_cli_params(args.param) if args.param else {"group_name": "VPN-Users"}

        print("\n--- Simulating AI Agent Query ---")
        print(f"Caller Account: {agent}")
        print(f"Command:        {cmd}")
        print(f"Parameters:     {params}")
        print(f"Ticket ID:      {args.ticket_id or 'None'}")
        print("---------------------------------")

        req = ProxyRequest(
            caller_account=agent,
            caller_password=pwd,
            command=cmd,
            parameters=params,
            ticket_id=args.ticket_id,
        )
        res = engine.process_request(req)

        print("\nResult:")
        print(f"Success:     {res.success}")
        print(f"Status Code: {res.status_code}")
        print(f"Message:     {res.message}")
        print(f"Duration:    {res.duration_ms:.2f} ms")
        if res.data is not None:
            print(f"Data:\n{json.dumps(res.data, indent=2)}")

        recent = engine.siem.get_recent_events(limit=1)
        if recent:
            print(f"\nGenerated SIEM Audit Event:\n{json.dumps(recent[0], indent=2)}")
        return

    # Run Proxy Server
    if args.run:
        server = AdProxyServer(config, engine)
        tls_status = "TLS 1.2+ HTTPS/LDAPS" if args.use_tls else "HTTP (dev)"
        print(f"Starting Active Directory LDAPS Proxy on {config.listen_host}:{config.listen_port} [{tls_status}]...")
        server.start(use_tls=args.use_tls)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
