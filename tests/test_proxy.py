"""
Comprehensive Security and Functional Test Suite for the Active Directory LDAPS Proxy.
Tests authentication, RBAC authorization, parameter sanitization, privilege escalation defense,
SIEM export formats, and extensible command registry.
"""

import json
import os
import sys
import unittest

# Ensure root path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ad_proxy.commands import escape_ldap_filter, registry
from ad_proxy.models import (
    AuditOutcome,
    AuthMode,
    CommandRiskLevel,
    ProxyRequest,
    SecretProvider,
    SiemFormat,
)
from ad_proxy.proxy_engine import AdProxyEngine
from ad_proxy.yaml_loader import build_proxy_config, load_yaml_raw


class TestActiveDirectoryProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load test configuration
        config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ad_proxy", "config.yaml"))
        raw_dict = load_yaml_raw(config_path)
        cls.config = build_proxy_config(raw_dict)
        cls.engine = AdProxyEngine(cls.config)

    def test_01_config_loading(self):
        """Validates that YAML configuration loads cleanly into typed dataclasses."""
        self.assertEqual(self.config.active_directory.domain_name, "corp.acme.internal")
        self.assertEqual(self.config.active_directory.base_dn, "DC=corp,DC=acme,DC=internal")
        self.assertIn("ai-triage-agent", self.config.allowed_service_accounts)
        self.assertIn("svc-it-helpdesk-agent", self.config.allowed_service_accounts)

    def test_02_ldap_filter_escaping(self):
        """Verifies RFC 4515 LDAP injection filter sanitization."""
        malicious = "admin*)(|(userPassword=*))"
        escaped = escape_ldap_filter(malicious)
        self.assertNotIn("*(", escaped)
        self.assertIn("\\2a", escaped)
        self.assertIn("\\28", escaped)
        self.assertIn("\\29", escaped)

    def test_03_authentication_success(self):
        """Verifies valid agent credentials successfully bind against Active Directory."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="get_domain_info",
            parameters={},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success, f"Expected success but got: {res.message}")
        self.assertEqual(res.status_code, "SUCCESS")
        self.assertIsNotNone(res.data)
        self.assertIn("defaultNamingContext", res.data)

    def test_04_authentication_failure(self):
        """Verifies invalid password triggers authentication failure and terminates connection."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="WrongPassword123!",
            command="get_domain_info",
            parameters={},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "AUTHENTICATION_FAILED")
        self.assertIn("Invalid Active Directory credentials", res.message)

    def test_05_unauthorized_account_blocked(self):
        """Verifies account not present in allowlist is blocked with FORBIDDEN."""
        req = ProxyRequest(
            caller_account="unauthorized-agent",
            caller_password="WrongPassword999!", # non-registered account
            command="get_domain_info",
            parameters={},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        # Auth will fail or caller check will fail
        self.assertIn(res.status_code, ("AUTHENTICATION_FAILED", "FORBIDDEN"))

    def test_06_rbac_blacklisted_command_blocked(self):
        """Verifies explicitly denied command in account policy is blocked immediately."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="reset_password",  # Explicitly in ai-triage-agent's denied_commands
            parameters={"user_identifier": "alex.rivera", "new_password": "NewSecretPassword2026!"},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertIn(res.status_code, ("FORBIDDEN", "CRITICAL_SECURITY_ALERT"))
        self.assertIn("explicitly denied", res.message)

    def test_07_protected_group_escalation_defense(self):
        """Verifies attempting to target 'Domain Admins' or privileged groups is blocked."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "alex.rivera",
                "group_name": "Domain Admins",  # Protected Tier-0 group
                "ticket_id": "CHG-9901",
            },
            ticket_id="CHG-9901",
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertIn(res.status_code, ("FORBIDDEN", "CRITICAL_SECURITY_ALERT"))
        self.assertIn("protected Tier-0", res.message)

    def test_08_rbac_missing_approval_ticket_blocked(self):
        """Verifies actions requiring an IT approval ticket fail if ticket_id is missing."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "alex.rivera",
                "group_name": "VPN-Users",
                # Omit ticket_id
            },
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "FORBIDDEN")
        self.assertIn("requires an IT approval ticket ID", res.message)

    def test_09_rbac_allowed_group_with_ticket_succeeds(self):
        """Verifies permitted write action with valid ticket succeeds."""
        req = ProxyRequest(
            caller_account="svc-it-helpdesk-agent",
            caller_password="HelpdeskSecretToken2026#",
            command="add_user_to_group",
            parameters={
                "user_identifier": "sarah.chen",
                "group_name": "VPN-Users",
                "ticket_id": "INC-88129",
            },
            ticket_id="INC-88129",
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success, f"Expected success: {res.message}")
        self.assertEqual(res.status_code, "SUCCESS")

    def test_10_read_group_members(self):
        """Verifies reading group members returns sanitized list of users."""
        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="list_group_members",
            parameters={"group_name": "VPN-Users"},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        self.assertIsInstance(res.data, list)
        self.assertTrue(len(res.data) >= 1)
        # Ensure password hash is not exposed
        first_user = res.data[0]
        self.assertNotIn("password", first_user)
        self.assertNotIn("unicodepwd", first_user)

    def test_11_siem_event_emission(self):
        """Verifies SIEM auditing records events in both ECS JSON and CEF formats."""
        recent = self.engine.siem.get_recent_events(limit=5)
        self.assertTrue(len(recent) > 0)
        latest = recent[0]
        self.assertIn("caller_account", latest)
        self.assertIn("outcome", latest)
        self.assertIn("duration_ms", latest)

        # Test CEF format generator
        from ad_proxy.models import AuditEvent, AuditOutcome
        sample_event = AuditEvent(
            event_id="test-evt-1",
            timestamp="2026-11-08T08:30:00Z",
            caller_account="ai-triage-agent",
            client_ip="10.0.4.15",
            command="list_group_members",
            target_dn="CN=VPN-Users,OU=Groups,DC=corp,DC=acme,DC=internal",
            filter_string="(&(objectCategory=group)(cn=VPN-Users))",
            outcome=AuditOutcome.SUCCESS,
            status_code="SUCCESS",
            message="Executed successfully",
            duration_ms=12.4,
            domain="corp.acme.internal",
        )
        cef_str = self.engine.siem._format_cef(sample_event)
        self.assertTrue(cef_str.startswith("CEF:0|EnterpriseSecurity|ActiveDirectoryProxy|1.0|SUCCESS|list_group_members|3|"))
        self.assertIn("suser=ai-triage-agent", cef_str)

        # Test ECS format generator
        ecs_str = self.engine.siem._format_ecs(sample_event)
        ecs_data = json.loads(ecs_str)
        self.assertEqual(ecs_data["user"]["name"], "ai-triage-agent")
        self.assertEqual(ecs_data["active_directory"]["command"], "list_group_members")
        self.assertEqual(ecs_data["event"]["outcome"], "success")

    def test_12_extensible_command_registry(self):
        """Verifies that new custom AD commands can be registered and executed seamlessly."""
        # Register custom command
        @registry.register(
            name="custom_ping_ou",
            description="Test custom registered AD command",
            category="system",
            risk_level=CommandRiskLevel.LOW,
            required_params=["ou_name"],
        )
        def handle_custom_ping(client, base_dn, params):
            return {"ou_name": params["ou_name"], "status": "active_replica"}

        # Temporarily permit for ai-triage-agent
        acc = self.engine.rbac.get_service_account("ai-triage-agent")
        acc.permitted_commands.append("custom_ping_ou")

        req = ProxyRequest(
            caller_account="ai-triage-agent",
            caller_password="AgentSecurePassword2026!",
            command="custom_ping_ou",
            parameters={"ou_name": "OU=Users"},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        self.assertEqual(res.data["ou_name"], "OU=Users")

        # Cleanup
        acc.permitted_commands.remove("custom_ping_ou")
        registry.remove_command("custom_ping_ou")

    def test_13_splunk_hec_log_formatting(self):
        """Verifies SIEM formatting conforms to Splunk HTTP Event Collector (HEC) JSON schema."""
        from ad_proxy.models import AuditEvent, AuditOutcome
        sample_event = AuditEvent(
            event_id="splunk-evt-101",
            timestamp="2026-11-08T09:15:30Z",
            caller_account="ai-triage-agent",
            client_ip="10.0.8.22",
            command="search_users",
            target_dn="OU=Engineering,DC=corp,DC=acme,DC=internal",
            filter_string="(&(objectCategory=person)(sAMAccountName=alex*))",
            outcome=AuditOutcome.SUCCESS,
            status_code="SUCCESS",
            message="Search completed successfully",
            duration_ms=4.82,
            domain="corp.acme.internal",
            parameters={"query": "alex"},
        )
        splunk_json_str = self.engine.siem._format_splunk_hec(sample_event)
        data = json.loads(splunk_json_str)

        # Splunk HEC envelope keys
        self.assertIn("time", data)
        self.assertIsInstance(data["time"], (int, float))
        self.assertIn("host", data)
        self.assertIn("source", data)
        self.assertEqual(data["source"], "ad-ldaps-proxy")
        self.assertIn("sourcetype", data)
        self.assertEqual(data["sourcetype"], "active_directory:proxy:audit")
        self.assertIn("index", data)
        self.assertEqual(data["index"], "active_directory")

        # Nested Splunk event payload
        event_body = data["event"]
        self.assertEqual(event_body["event_id"], "splunk-evt-101")
        self.assertEqual(event_body["caller_account"], "ai-triage-agent")
        self.assertEqual(event_body["command"], "search_users")
        self.assertEqual(event_body["outcome"], "SUCCESS")
        self.assertEqual(event_body["domain"], "corp.acme.internal")

        # Test Splunk high-severity rogue agent threat enrichment
        sample_rogue = AuditEvent(
            event_id="splunk-rogue-102",
            timestamp="2026-11-08T09:16:00Z",
            caller_account="ai-triage-agent",
            client_ip="10.0.8.22",
            command="reset_password",
            target_dn="administrator",
            filter_string=None,
            outcome=AuditOutcome.SECURITY_ALERT_ROGUE_AGENT,
            status_code="CRITICAL_SECURITY_ALERT",
            message="Rogue password reset blocked",
            duration_ms=0.91,
            domain="corp.acme.internal",
            is_high_severity_alert=True,
            alert_rule="ROGUE_AGENT_ADMIN_PASSWORD_RESET_ATTEMPT",
        )
        rogue_splunk_str = self.engine.siem._format_splunk_hec(sample_rogue)
        rogue_data = json.loads(rogue_splunk_str)
        self.assertIn("threat", rogue_data["event"])
        self.assertEqual(rogue_data["event"]["threat"]["indicator"], "ROGUE_OR_HALLUCINATING_AGENT_DETECTED")
        self.assertEqual(rogue_data["event"]["threat"]["severity"], "CRITICAL")
        self.assertEqual(rogue_data["event"]["threat"]["risk_score"], 100)

    def test_14_wazuh_json_log_formatting(self):
        """Verifies SIEM formatting conforms to Wazuh native JSON alert schema and rule levels."""
        from ad_proxy.models import AuditEvent, AuditOutcome
        sample_event = AuditEvent(
            event_id="wazuh-evt-201",
            timestamp="2026-11-08T09:20:00Z",
            caller_account="svc-it-helpdesk-agent",
            client_ip="10.0.9.55",
            command="unlock_account",
            target_dn="CN=John Doe,OU=Users,DC=corp,DC=acme,DC=internal",
            filter_string=None,
            outcome=AuditOutcome.SUCCESS,
            status_code="SUCCESS",
            message="Account unlocked successfully",
            duration_ms=15.1,
            domain="corp.acme.internal",
        )
        wazuh_json_str = self.engine.siem._format_wazuh_json(sample_event)
        data = json.loads(wazuh_json_str)

        # Wazuh core schema verification
        self.assertIn("timestamp", data)
        self.assertIn("agent", data)
        self.assertEqual(data["agent"]["name"], "ad-proxy-gateway")
        self.assertIn("manager", data)
        self.assertEqual(data["manager"]["name"], "wazuh-manager")
        self.assertIn("rule", data)
        self.assertEqual(data["rule"]["level"], 3)  # Info level for successful operation
        self.assertIn("active_directory", data["rule"]["groups"])
        self.assertIn("decoder", data)
        self.assertEqual(data["decoder"]["name"], "ad_proxy_json")
        self.assertIn("data", data)
        self.assertIn("ad_proxy", data["data"])
        self.assertEqual(data["data"]["ad_proxy"]["command"], "unlock_account")
        self.assertIn("location", data)
        self.assertIn("full_log", data)

        # Test Wazuh rule level elevation on rogue agent critical alert (Rule Level 12)
        sample_rogue = AuditEvent(
            event_id="wazuh-rogue-202",
            timestamp="2026-11-08T09:22:00Z",
            caller_account="ai-triage-agent",
            client_ip="10.0.9.55",
            command="add_user_to_group",
            target_dn="Domain Admins",
            filter_string=None,
            outcome=AuditOutcome.SECURITY_ALERT_ROGUE_AGENT,
            status_code="CRITICAL_SECURITY_ALERT",
            message="Tier-0 Domain Admins tampering attempt intercepted",
            duration_ms=1.12,
            domain="corp.acme.internal",
            is_high_severity_alert=True,
            alert_rule="ROGUE_AGENT_CRITICAL_GROUP_TARGET",
        )
        rogue_wazuh_str = self.engine.siem._format_wazuh_json(sample_rogue)
        rogue_data = json.loads(rogue_wazuh_str)
        self.assertEqual(rogue_data["rule"]["level"], 12)  # High security level in Wazuh
        self.assertIn("rogue_agent", rogue_data["rule"]["groups"])
        self.assertIn("threat", rogue_data["data"]["ad_proxy"])
        self.assertEqual(rogue_data["data"]["ad_proxy"]["threat"]["indicator"], "ROGUE_OR_HALLUCINATING_AGENT_DETECTED")

    def test_15_siem_splunk_and_wazuh_destination_dispatch(self):
        """Verifies configured Splunk and Wazuh destinations process events without exception."""
        from ad_proxy.models import AuditEvent, AuditOutcome, SiemConfig, SiemFormat, SplunkConfig, WazuhConfig
        from ad_proxy.siem_logger import SiemAuditLogger

        temp_wazuh_file = "./logs/test_wazuh_alerts.json"
        siem_cfg = SiemConfig(
            enabled=True,
            format=SiemFormat.ECS,
            destinations=["splunk", "wazuh"],
            splunk=SplunkConfig(
                enabled=True,
                hec_url="https://127.0.0.1:8088/services/collector/event",
                hec_token="test-token",
                verify_ssl=False,
            ),
            wazuh=WazuhConfig(
                enabled=True,
                host=None,  # skip network socket in test, test localfile
                alerts_file=temp_wazuh_file,
            ),
        )
        logger = SiemAuditLogger(siem_cfg)
        test_evt = AuditEvent(
            event_id="dest-dispatch-301",
            timestamp="2026-11-08T09:30:00Z",
            caller_account="ai-triage-agent",
            client_ip="127.0.0.1",
            command="list_group_members",
            target_dn="VPN-Users",
            filter_string=None,
            outcome=AuditOutcome.SUCCESS,
            status_code="SUCCESS",
            message="Test dispatch",
            duration_ms=2.1,
            domain="corp.acme.internal",
        )
        # Should not throw exception
        logger.log(test_evt)
        self.assertTrue(os.path.exists(temp_wazuh_file))
        with open(temp_wazuh_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("dest-dispatch-301", content)
        self.assertIn("ad_proxy_json", content)
        # Clean up test file
        try:
            os.remove(temp_wazuh_file)
        except Exception:
            pass

    def test_16_procedure_step1_wrong_password_authentication_failure(self):
        """Test Procedure Step 1: Verify AI agent with wrong password fails authentication."""
        req = ProxyRequest(
            caller_account="svc-group-viewer-agent",
            caller_password="BadPassword999!",
            command="list_group_members",
            parameters={"group_name": "VPN-Users"},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "AUTHENTICATION_FAILED")
        self.assertIn("Invalid Active Directory credentials", res.message)

    def test_17_procedure_step2_correct_password_forbidden_request(self):
        """Test Procedure Step 2: Verify AI agent with correct password but forbidden request is blocked."""
        # svc-group-viewer-agent is ONLY permitted 'list_group_members'. Attempting 'search_users' is forbidden.
        req = ProxyRequest(
            caller_account="svc-group-viewer-agent",
            caller_password="GroupViewerSecret2026!",
            command="search_users",
            parameters={"query": "alex"},
        )
        res = self.engine.process_request(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status_code, "FORBIDDEN")
        self.assertTrue("explicitly denied" in res.message or "not permitted" in res.message)

    def test_18_procedure_step3_correct_password_allowed_group_view_request(self):
        """Test Procedure Step 3: Verify AI agent with correct password and allowed request succeeds."""
        req = ProxyRequest(
            caller_account="svc-group-viewer-agent",
            caller_password="GroupViewerSecret2026!",
            command="list_group_members",
            parameters={"group_name": "VPN-Users"},
        )
        res = self.engine.process_request(req)
        self.assertTrue(res.success)
        self.assertEqual(res.status_code, "SUCCESS")
        self.assertIsInstance(res.data, list)
        self.assertTrue(len(res.data) >= 1)
        self.assertEqual(res.data[0]["displayName"], "Alex Rivera")


def run_all_tests() -> bool:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestActiveDirectoryProxy))
    try:
        from tests.test_security_audit import SecurityAuditTest
        suite.addTests(loader.loadTestsFromTestCase(SecurityAuditTest))
    except ImportError:
        pass
    try:
        from tests.test_rogue_agent_alerts import RogueAgentAlertFunctionalTest
        suite.addTests(loader.loadTestsFromTestCase(RogueAgentAlertFunctionalTest))
    except ImportError:
        pass
    try:
        from tests.test_docker_and_linux_install import TestDockerAndLinuxInstallation
        suite.addTests(loader.loadTestsFromTestCase(TestDockerAndLinuxInstallation))
    except ImportError:
        pass

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
