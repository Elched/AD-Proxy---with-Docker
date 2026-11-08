"""
Enterprise SIEM Auditing Engine.
Outputs structured audit events in CEF (ArcSight/Splunk), ECS (Elastic Common Schema JSON),
and RFC 5424 Syslog formats. Supports file, stdout, remote syslog (UDP/TCP/TLS), and webhook exporters.
"""

from collections import deque
from datetime import datetime, timezone
import json
import logging
import os
import socket
import ssl
from typing import Any, Deque, Dict, List, Optional
import urllib.request
from .models import AuditEvent, AuditOutcome, SiemConfig, SiemFormat

logger = logging.getLogger("ad_proxy.siem")


class SiemAuditLogger:
    """Enterprise-grade audit logger compliant with SIEM and compliance regulations."""

    def __init__(self, config: SiemConfig):
        self.config = config
        self._recent_events: Deque[Dict[str, Any]] = deque(maxlen=200)

        # Ensure directory for file logging exists
        if "file" in self.config.destinations and self.config.log_file_path:
            dir_path = os.path.dirname(self.config.log_file_path)
            if dir_path and not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                except Exception as e:
                    logger.warning("Could not create log directory '%s': %s", dir_path, e)

    def log(self, event: AuditEvent):
        """Records an audit event across all configured SIEM destinations."""
        if not self.config.enabled:
            return

        # High-severity alert logger for rogue or hallucinating agents
        if getattr(event, "is_high_severity_alert", False):
            logger.critical(
                "[CRITICAL SECURITY ALERT - ROGUE AGENT DETECTED] Account: '%s' | Command: '%s' | Target: '%s' | Rule: '%s' | %s",
                event.caller_account,
                event.command,
                event.target_dn or "N/A",
                getattr(event, "alert_rule", "ROGUE_AGENT_ALERT"),
                event.message,
            )

        # Always save structured dict in memory for UI / API access
        event_dict = self._to_event_dict(event)
        self._recent_events.appendleft(event_dict)

        formatted_str = self._format_event(event)

        # Export to destinations
        for dest in self.config.destinations:
            dest_lower = dest.lower()
            if dest_lower == "stdout":
                prefix = "[CRITICAL-SECURITY-ALERT] [SIEM]" if getattr(event, "is_high_severity_alert", False) else "[AUDIT-SIEM]"
                print(f"{prefix} {formatted_str}", flush=True)
            elif dest_lower == "file":
                self._write_file(formatted_str)
            elif dest_lower == "syslog":
                self._send_syslog(formatted_str)
            elif dest_lower == "webhook":
                self._send_webhook(event_dict)
            elif dest_lower in ("splunk", "splunk_hec"):
                self._send_splunk(event)
            elif dest_lower in ("wazuh", "wazuh_json"):
                self._send_wazuh(event)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns in-memory audit log stream."""
        return list(self._recent_events)[:limit]

    def _to_event_dict(self, e: AuditEvent) -> Dict[str, Any]:
        return {
            "event_id": e.event_id,
            "timestamp": e.timestamp or datetime.now(timezone.utc).isoformat(),
            "caller_account": e.caller_account,
            "client_ip": e.client_ip,
            "command": e.command,
            "target_dn": e.target_dn,
            "filter_string": e.filter_string,
            "outcome": e.outcome.value,
            "status_code": e.status_code,
            "message": e.message,
            "duration_ms": round(e.duration_ms, 2),
            "parameters": e.parameters,
            "details": e.details,
            "domain": e.domain,
            "severity": self._get_severity(e),
            "is_high_severity_alert": getattr(e, "is_high_severity_alert", False),
            "alert_rule": getattr(e, "alert_rule", None),
        }

    def _format_event(self, e: AuditEvent) -> str:
        if self.config.format == SiemFormat.CEF:
            return self._format_cef(e)
        elif self.config.format == SiemFormat.SYSLOG:
            return self._format_syslog_rfc5424(e)
        elif self.config.format == SiemFormat.SPLUNK_HEC:
            return self._format_splunk_hec(e)
        elif self.config.format == SiemFormat.WAZUH_JSON:
            return self._format_wazuh_json(e)
        else:
            return self._format_ecs(e)

    def _get_severity(self, e: AuditEvent) -> int:
        """Maps outcome to CEF severity (0-10 scale). High-severity rogue agent attempts receive 10."""
        if getattr(e, "is_high_severity_alert", False) or e.outcome == AuditOutcome.SECURITY_ALERT_ROGUE_AGENT:
            return 10
        if e.outcome == AuditOutcome.SUCCESS:
            return 3
        elif e.outcome in (AuditOutcome.AUTH_FAILED, AuditOutcome.FORBIDDEN_CALLER):
            return 8
        elif e.outcome in (AuditOutcome.FORBIDDEN_COMMAND, AuditOutcome.RESTRICTED_TARGET):
            return 7
        return getattr(e, "severity", 5)

    def _format_cef(self, e: AuditEvent) -> str:
        """
        Common Event Format (CEF) standard string:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        """
        sev = self._get_severity(e)
        escaped_msg = e.message.replace("|", "\\|")
        ext_parts = [
            f"src={e.client_ip}",
            f"suser={e.caller_account}",
            f"cs1Label=Command cs1={e.command}",
            f"outcome={e.outcome.value}",
            f"cn1Label=DurationMs cn1={int(e.duration_ms)}",
            f"msg={escaped_msg}",
        ]
        if e.target_dn:
            ext_parts.append(f"cs2Label=TargetDN cs2={e.target_dn}")
        if e.filter_string:
            escaped_filter = e.filter_string.replace("=", "\\=")
            ext_parts.append(f"cs3Label=LdapFilter cs3={escaped_filter}")
        if e.domain:
            ext_parts.append(f"cs4Label=Domain cs4={e.domain}")
        if getattr(e, "is_high_severity_alert", False):
            ext_parts.append("cat=Threat/RogueAgent")
            ext_parts.append("act=BLOCKED_CRITICAL_SECURITY_ALERT")
            rule = getattr(e, "alert_rule", "ROGUE_AGENT_CRITICAL_TARGET_VIOLATION") or "ROGUE_AGENT_CRITICAL_TARGET_VIOLATION"
            ext_parts.append(f"cs5Label=AlertRule cs5={rule}")

        extension = " ".join(ext_parts)
        return f"CEF:0|EnterpriseSecurity|ActiveDirectoryProxy|1.0|{e.status_code}|{e.command}|{sev}|{extension}"

    def _format_ecs(self, e: AuditEvent) -> str:
        """Elastic Common Schema (ECS) JSON representation."""
        is_success = e.outcome == AuditOutcome.SUCCESS
        sev = self._get_severity(e)
        categories = ["iam", "network"]
        if getattr(e, "is_high_severity_alert", False):
            categories.extend(["threat", "security_violation"])

        ecs_obj = {
            "@timestamp": e.timestamp or datetime.now(timezone.utc).isoformat(),
            "event": {
                "id": e.event_id,
                "category": categories,
                "type": ["access", "denial"] if not is_success else ["access", "protocol"],
                "action": f"ad_proxy.{e.command}",
                "outcome": "success" if is_success else "failure",
                "severity": sev,
                "duration": int(e.duration_ms * 1_000_000),  # nanoseconds in ECS
                "reason": e.message,
            },
            "source": {
                "ip": e.client_ip,
            },
            "user": {
                "name": e.caller_account,
                "domain": e.domain,
            },
            "active_directory": {
                "command": e.command,
                "status_code": e.status_code,
                "target_dn": e.target_dn,
                "filter": e.filter_string,
                "parameters": e.parameters,
            },
            "service": {
                "name": "ad-ldaps-proxy",
                "version": "1.0.0",
            },
        }

        if getattr(e, "is_high_severity_alert", False):
            ecs_obj["threat"] = {
                "indicator": "ROGUE_OR_HALLUCINATING_AGENT_DETECTED",
                "rule": getattr(e, "alert_rule", "CRITICAL_TIER0_TARGET_VIOLATION"),
                "severity": "CRITICAL",
                "risk_score": 100,
                "action": "BLOCKED_TERMINATED",
            }

        return json.dumps(ecs_obj, separators=(",", ":"))

    def _format_syslog_rfc5424(self, e: AuditEvent) -> str:
        """RFC 5424 Syslog line with structured data."""
        # Facility authpriv (10) * 8 + Severity
        prival = 80 + (3 if e.outcome == AuditOutcome.SUCCESS else 1)
        ts = e.timestamp or datetime.now(timezone.utc).isoformat()
        hostname = socket.gethostname()
        cef_payload = self._format_cef(e)
        return f"<{prival}>1 {ts} {hostname} ad-proxy {os.getpid()} AUDIT - {cef_payload}"

    def _write_file(self, content: str):
        path = self.config.log_file_path
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(content + "\n")
        except Exception as e:
            # Fallback to local logs directory if system directory is restricted
            fallback_path = "./logs/audit.log"
            try:
                os.makedirs("./logs", exist_ok=True)
                with open(fallback_path, "a", encoding="utf-8") as f:
                    f.write(content + "\n")
            except Exception:
                logger.error("Failed to write SIEM audit event to log file %s: %s", path, e)

    def _send_syslog(self, content: str):
        if not self.config.syslog_host:
            return
        host = self.config.syslog_host
        port = self.config.syslog_port
        proto = self.config.syslog_protocol.upper()

        try:
            data = (content + "\n").encode("utf-8")
            if proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(data, (host, port))
                sock.close()
            elif proto in ("TCP", "TLS"):
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(3.0)
                if proto == "TLS":
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(raw_sock, server_hostname=host)
                else:
                    s = raw_sock
                s.connect((host, port))
                s.sendall(data)
                s.close()
        except Exception as e:
            logger.debug("Syslog export to %s:%d failed: %s", host, port, e)

    def _send_webhook(self, event_dict: Dict[str, Any]):
        if not self.config.webhook_url:
            return
        try:
            headers = {"Content-Type": "application/json"}
            if self.config.webhook_token:
                headers["Authorization"] = f"Bearer {self.config.webhook_token}"
            req = urllib.request.Request(
                self.config.webhook_url,
                data=json.dumps(event_dict).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                _ = resp.read()
        except Exception as e:
            logger.debug("Webhook SIEM forward to %s failed: %s", self.config.webhook_url, e)

    def _format_splunk_hec(self, e: AuditEvent) -> str:
        """
        Splunk HTTP Event Collector (HEC) JSON Event Format:
        {
          "time": <epoch_seconds>,
          "host": "<hostname>",
          "source": "ad-ldaps-proxy",
          "sourcetype": "active_directory:proxy:audit",
          "index": "active_directory",
          "event": { ... }
        }
        """
        try:
            ts_str = e.timestamp or datetime.now(timezone.utc).isoformat()
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            epoch_time = dt.timestamp()
        except Exception:
            epoch_time = datetime.now(timezone.utc).timestamp()

        splunk_cfg = self.config.splunk
        host_val = socket.gethostname()
        source_val = splunk_cfg.source if splunk_cfg else "ad-ldaps-proxy"
        sourcetype_val = splunk_cfg.sourcetype if splunk_cfg else "active_directory:proxy:audit"
        index_val = splunk_cfg.index if splunk_cfg else "active_directory"

        event_payload = self._to_event_dict(e)
        if getattr(e, "is_high_severity_alert", False):
            event_payload["threat"] = {
                "indicator": "ROGUE_OR_HALLUCINATING_AGENT_DETECTED",
                "rule": getattr(e, "alert_rule", "ROGUE_AGENT_ALERT"),
                "severity": "CRITICAL",
                "risk_score": 100,
                "action": "BLOCKED_TERMINATED",
            }

        splunk_envelope = {
            "time": round(epoch_time, 3),
            "host": host_val,
            "source": source_val,
            "sourcetype": sourcetype_val,
            "index": index_val,
            "event": event_payload,
        }
        return json.dumps(splunk_envelope, separators=(",", ":"))

    def _format_wazuh_json(self, e: AuditEvent) -> str:
        """
        Wazuh SIEM / XDR JSON Alert & Decoded Event Schema:
        Conforms to Wazuh analysis engine standards (agent, manager, rule, decoder, data, location, full_log).
        """
        wazuh_cfg = self.config.wazuh
        is_alert = getattr(e, "is_high_severity_alert", False) or e.outcome == AuditOutcome.SECURITY_ALERT_ROGUE_AGENT
        is_success = e.outcome == AuditOutcome.SUCCESS

        # Wazuh Rule Levels: 3 (info), 7 (warning/policy violation), 12 (critical security threat)
        rule_level = 12 if is_alert else (3 if is_success else 7)
        rule_id = "100201" if is_alert else ("100200" if is_success else "100202")

        groups = ["active_directory", "proxy"]
        if is_alert:
            groups.extend(["security_alert", "threat_detection", "rogue_agent"])
        elif not is_success:
            groups.extend(["authentication_failed", "access_denied"])
        else:
            groups.append("audit")

        agent_id = wazuh_cfg.agent_id if wazuh_cfg else "000"
        agent_name = wazuh_cfg.agent_name if wazuh_cfg else "ad-proxy-gateway"
        manager_name = wazuh_cfg.manager_name if wazuh_cfg else "wazuh-manager"
        location = wazuh_cfg.location if wazuh_cfg else "active_directory_proxy"

        data_payload = self._to_event_dict(e)
        if is_alert:
            data_payload["threat"] = {
                "indicator": "ROGUE_OR_HALLUCINATING_AGENT_DETECTED",
                "rule": getattr(e, "alert_rule", "ROGUE_AGENT_ALERT"),
                "severity": "CRITICAL",
                "risk_score": 100,
                "action": "BLOCKED_TERMINATED",
            }

        wazuh_event = {
            "timestamp": e.timestamp or datetime.now(timezone.utc).isoformat(),
            "agent": {
                "id": agent_id,
                "name": agent_name,
                "ip": e.client_ip or "127.0.0.1",
            },
            "manager": {
                "name": manager_name,
            },
            "rule": {
                "id": rule_id,
                "level": rule_level,
                "description": f"Active Directory LDAPS Proxy: {e.command} - {e.outcome.value} ({e.status_code})",
                "groups": groups,
                "firedtimes": 1,
            },
            "decoder": {
                "name": "ad_proxy_json",
            },
            "data": {
                "ad_proxy": data_payload,
            },
            "location": location,
            "full_log": f"ActiveDirectoryProxy [{e.status_code}] caller='{e.caller_account}' cmd='{e.command}' outcome='{e.outcome.value}' target='{e.target_dn or 'N/A'}' msg='{e.message}'",
        }
        return json.dumps(wazuh_event, separators=(",", ":"))

    def _send_splunk(self, e: AuditEvent):
        """Forwards formatted event to Splunk HTTP Event Collector (HEC)."""
        splunk_cfg = self.config.splunk
        hec_url = (splunk_cfg.hec_url if splunk_cfg else None) or self.config.webhook_url
        token = (splunk_cfg.hec_token if splunk_cfg else None) or self.config.webhook_token
        if not hec_url:
            return

        payload_str = self._format_splunk_hec(e)
        headers = {"Content-Type": "application/json"}
        if token:
            # Splunk HEC standard authorization
            headers["Authorization"] = f"Splunk {token}"

        try:
            ctx = None
            if splunk_cfg and not splunk_cfg.verify_ssl and hec_url.startswith("https://"):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                hec_url,
                data=payload_str.encode("utf-8"),
                headers=headers,
                method="POST",
            )
            timeout = splunk_cfg.timeout_seconds if splunk_cfg else 3.0
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                _ = resp.read()
        except Exception as ex:
            logger.debug("Splunk HEC forwarding to %s failed: %s", hec_url, ex)

    def _send_wazuh(self, e: AuditEvent):
        """Forwards formatted event to Wazuh (via monitored alert file and/or syslog socket)."""
        wazuh_cfg = self.config.wazuh
        payload_str = self._format_wazuh_json(e)

        # 1. Monitored alert file ingestion (standard Wazuh localfile JSON collection)
        alerts_file = (wazuh_cfg.alerts_file if wazuh_cfg else None) or "./logs/wazuh_alerts.json"
        if alerts_file:
            try:
                dir_path = os.path.dirname(alerts_file)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)
                with open(alerts_file, "a", encoding="utf-8") as f:
                    f.write(payload_str + "\n")
            except Exception as ex:
                logger.debug("Wazuh alerts file write to %s failed: %s", alerts_file, ex)

        # 2. Network socket transmission to Wazuh manager if host configured
        if wazuh_cfg and wazuh_cfg.host:
            host = wazuh_cfg.host
            port = wazuh_cfg.port or 514
            proto = (wazuh_cfg.protocol or "UDP").upper()
            try:
                data = (payload_str + "\n").encode("utf-8")
                if proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(data, (host, port))
                    sock.close()
                elif proto == "TCP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(wazuh_cfg.timeout_seconds or 3.0)
                    sock.connect((host, port))
                    sock.sendall(data)
                    sock.close()
            except Exception as ex:
                logger.debug("Wazuh manager network export to %s:%d failed: %s", host, port, ex)
