# Active Directory Secure LDAPS Proxy
## AI Agent Functionality Test Procedure & Security Verification Guide

This operational procedure guides security engineers, system administrators, and AI platform teams through provisioning a dedicated **AI Agent Active Directory Service Account**, locking it down with least-privilege permissions in the **AD Proxy App** (restricting it strictly to viewing users in Active Directory groups), and running a three-phase authentication and authorization verification test.

---

## Table of Contents

1. [Test Objectives & Scope](#1-test-objectives--scope)
2. [Step 1: Create the AI Agent Service Account in Active Directory](#step-1-create-the-ai-agent-service-account-in-active-directory)
   - [Option A: Production Windows Server Active Directory (PowerShell)](#option-a-production-windows-server-active-directory-powershell)
   - [Option B: Sandboxed / Local Test Directory Engine (Built-in)](#option-b-sandboxed--local-test-directory-engine-built-in)
3. [Step 2: Configure the AI Agent Policy in the AD Proxy App](#step-2-configure-the-ai-agent-policy-in-the-ad-proxy-app)
   - [Policy Definition (Least Privilege: Group View Only)](#policy-definition-least-privilege-group-view-only)
   - [Validating and Applying the Configuration](#validating-and-applying-the-configuration)
4. [Step 3: Test Phase 1 — Authenticating with WRONG Password](#step-3-test-phase-1--authenticating-with-wrong-password)
   - [Execution Methods (cURL, Python, Web UI)](#phase-1-execution-methods)
   - [Expected Response Payload & Log Outputs](#phase-1-expected-response-payload--log-outputs)
5. [Step 4: Test Phase 2 — Authenticating with CORRECT Password but FORBIDDEN Request](#step-4-test-phase-2--authenticating-with-correct-password-but-forbidden-request)
   - [Execution Methods (cURL, Python, Web UI)](#phase-2-execution-methods)
   - [Expected Response Payload & Log Outputs](#phase-2-expected-response-payload--log-outputs)
   - [Variant: Critical Tier-0 Escalation Attempt (`Domain Admins`)](#phase-2-variant-critical-tier-0-escalation-attempt)
6. [Step 5: Test Phase 3 — Authenticating with CORRECT Password and ALLOWED Request](#step-5-test-phase-3--authenticating-with-correct-password-and-allowed-request)
   - [Execution Methods (cURL, Python, Web UI)](#phase-3-execution-methods)
   - [Expected Response Payload & Log Outputs](#phase-3-expected-response-payload--log-outputs)
7. [Step 6: Automated Verification via Regression Suite](#step-6-automated-verification-via-regression-suite)
8. [Summary & Verification Matrix](#summary--verification-matrix)

---

## 1. Test Objectives & Scope

| Parameter | Specification |
| :--- | :--- |
| **Agent Identity** | `svc-group-viewer-agent` (sAMAccountName) |
| **Account UPN** | `svc-group-viewer-agent@corp.acme.internal` |
| **Domain Base DN** | `DC=corp,DC=acme,DC=internal` |
| **Valid Password** | `GroupViewerSecret2026!` (min 12 chars, mixed case, numbers, symbols) |
| **Invalid Password** | `WrongPassword123!` |
| **Assigned Role** | Group Membership Viewer AI Agent |
| **Permitted Commands** | `list_group_members` (strictly read-only group member enumeration) |
| **Denied Commands** | `search_users`, `get_user_attributes`, `add_user_to_group`, `remove_user_from_group`, `enable_account`, `disable_account`, `unlock_account`, `reset_password`, `custom_search_filter` |
| **Target Security Groups** | Allowed: `VPN-Users`, `Developers`, `Helpdesk-Tier1` · Restricted: `Domain Admins`, `Enterprise Admins` |

---

## Step 1: Create the AI Agent Service Account in Active Directory

### Option A: Production Windows Server Active Directory (PowerShell)

On a Windows Server Domain Controller (or management workstation with RSAT tools installed), run the following PowerShell commands in an elevated PowerShell session:

```powershell
# 1. Target Domain Controller and Base DN
$DomainBaseDN = "DC=corp,DC=acme,DC=internal"
$DomainController = "dc01.corp.acme.internal"

# 2. Ensure the Dedicated Service Accounts Organizational Unit (OU) Exists
$OuPath = "OU=ServiceAccounts,$DomainBaseDN"
if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$OuPath'")) {
    New-ADOrganizationalUnit `
        -Name "ServiceAccounts" `
        -Path $DomainBaseDN `
        -ProtectedFromAccidentalDeletion $true `
        -Server $DomainController
    Write-Host "[+] Created OU: $OuPath" -ForegroundColor Green
}

# 3. Create the AI Agent Service Account
$AccountName = "svc-group-viewer-agent"
$PasswordPlain = "GroupViewerSecret2026!"
$SecurePassword = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force

New-ADUser `
    -Name $AccountName `
    -SamAccountName $AccountName `
    -UserPrincipalName "$AccountName@corp.acme.internal" `
    -DisplayName "Group Membership Viewer AI Agent" `
    -Description "AI Agent restricted strictly to viewing users in Active Directory groups" `
    -Path $OuPath `
    -AccountPassword $SecurePassword `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -CannotChangePassword $true `
    -Server $DomainController

Write-Host "[+] Successfully created Active Directory Service Account: $AccountName" -ForegroundColor Green

# 4. Optional: Assign the Account to the Non-Privileged AI Service Accounts Security Group
$GroupName = "AI-Service-Accounts"
if (Get-ADGroup -Filter "sAMAccountName -eq '$GroupName'") {
    Add-ADGroupMember -Identity $GroupName -Members $AccountName -Server $DomainController
    Write-Host "[+] Added $AccountName to security group $GroupName" -ForegroundColor Green
}
```

### Option B: Sandboxed / Local Test Directory Engine (Built-in)

For local development, containerized environments, or automated CI/CD testing where a physical Windows Domain Controller is not present, the proxy includes an in-memory simulated directory partition.

The service account is registered in `ad_proxy/ldap_client.py`:

```python
# Located in: ad_proxy/ldap_client.py -> ActiveDirectoryLdapClient._initialize_mock_ad_database()
"svc-group-viewer-agent": {
    "sAMAccountName": "svc-group-viewer-agent",
    "userPrincipalName": f"svc-group-viewer-agent@{self.config.domain_name}",
    "displayName": "Group Membership Viewer AI Agent",
    "mail": f"group-viewer@{self.config.domain_name}",
    "department": "Security Auditing",
    "title": "AI Group Auditor Bot",
    "distinguishedName": f"CN=svc-group-viewer-agent,OU=ServiceAccounts,{base}",
    "userAccountControl": 512,  # 512 = NORMAL_ACCOUNT, enabled
    "password": "GroupViewerSecret2026!",
    "disabled": False,
    "locked": False,
    "memberOf": [f"CN=AI-Service-Accounts,OU=Groups,{base}"],
}
```

*Note: This account is already pre-configured in the repository database so that all steps below work immediately out of the box.*

---

## Step 2: Configure the AI Agent Policy in the AD Proxy App

### Policy Definition (Least Privilege: Group View Only)

Edit `ad_proxy/config.yaml` (or configure via the **Policy Manager** tab in the Web Console) and ensure the following policy block is added under `allowed_service_accounts:`:

```yaml
# ==============================================================================
# AI Agent Policy: Group Membership Viewer
# ==============================================================================
allowed_service_accounts:
  # ... other existing service accounts (ai-triage-agent, svc-it-helpdesk-agent) ...

  # Group Membership Viewer AI Agent (Restricted to viewing group members)
  - account_identifier: "svc-group-viewer-agent"
    description: "AI Agent restricted strictly to viewing users in Active Directory groups"
    permitted_commands:
      - "list_group_members"
    denied_commands:
      - "search_users"
      - "get_user_attributes"
      - "add_user_to_group"
      - "remove_user_from_group"
      - "enable_account"
      - "disable_account"
      - "unlock_account"
      - "reset_password"
      - "custom_search_filter"
    rules:
      - command: "list_group_members"
        allowed_groups:
          - "VPN-Users"
          - "Developers"
          - "Helpdesk-Tier1"
        restricted_groups:
          - "Domain Admins"
          - "Enterprise Admins"
          - "Schema Admins"
          - "Administrators"
```

### Validating and Applying the Configuration

Before executing queries, verify that the configuration passes schema validation and syntax checks:

```bash
# Validate configuration via CLI
python3 -m ad_proxy.cli --check
```

**Expected CLI Output:**
```text
[OK] Configuration successfully parsed from: /app/applet/ad_proxy/config.yaml
  - Active Directory Domain:     corp.acme.internal
  - Base DN:                     DC=corp,DC=acme,DC=internal
  - Domain Controllers:          dc01.corp.acme.internal, dc02.corp.acme.internal
  - Upstream Auth Mode:          service_account
  - Secret Provider:             env
  - SIEM Format:                 ecs
  - SIEM Destinations:           file, stdout
  - Splunk HEC Forwarder:        Enabled -> https://splunk-hec.corp.acme.internal:8088/services/collector/event
  - Wazuh XDR/SIEM Forwarder:    Enabled -> Host: wazuh-manager.corp.acme.internal:514 | Alert Log: ./logs/wazuh_alerts.json
  - Registered Service Accounts: 4
     * svc-group-viewer-agent (AI Agent restricted strictly to viewing users in Active Directory groups) -> Permitted: 1 commands
```

Alternatively, in the **Web Console (Port 3000)**:
1. Navigate to the **RBAC Policy Manager** tab.
2. Verify the policy for `svc-group-viewer-agent` appears with `Permitted: list_group_members`.
3. Click **"Validate & Dry Run"** to verify YAML schema without modifying disk.

---

## Step 3: Test Phase 1 — Authenticating with WRONG Password

In this phase, the AI agent attempts to query the proxy using an **invalid password** (`WrongPassword123!`).

### Phase 1: Execution Methods

#### Method 1: Using cURL against the REST Proxy Gateway
```bash
curl -s -X POST http://localhost:3000/api/proxy/execute \
  -H "Content-Type: application/json" \
  -d '{
    "caller_account": "svc-group-viewer-agent",
    "caller_password": "WrongPassword123!",
    "command": "list_group_members",
    "parameters": {
      "group_name": "VPN-Users"
    }
  }' | jq .
```

#### Method 2: Using Python Script / Interactive Terminal
```python
from ad_proxy.models import ProxyRequest
from ad_proxy.proxy_engine import AdProxyEngine
from ad_proxy.yaml_loader import build_proxy_config, load_yaml_raw

config = build_proxy_config(load_yaml_raw("ad_proxy/config.yaml"))
engine = AdProxyEngine(config)

req = ProxyRequest(
    caller_account="svc-group-viewer-agent",
    caller_password="WrongPassword123!",
    command="list_group_members",
    parameters={"group_name": "VPN-Users"},
)
res = engine.process_request(req)
print(f"Success: {res.success}")
print(f"Status Code: {res.status_code}")
print(f"Message: {res.message}")
```

#### Method 3: Using Web Console Agent Simulator
1. Open the browser to `http://localhost:3000`.
2. Under the **Agent Simulator** tab, select Scenario Preset **"7. Test Step 1: Wrong Password"**.
3. Click **"Execute LDAPS Proxy Request"**.

---

### Phase 1: Expected Response Payload & Log Outputs

#### 1. HTTP JSON API Response
```json
{
  "success": false,
  "status_code": "AUTHENTICATION_FAILED",
  "message": "Access Denied: Invalid Active Directory credentials for 'svc-group-viewer-agent'. Connection terminated.",
  "data": null,
  "request_id": "97e6bf2a-4db1-455b-866d-cb5c8a4eb0fa",
  "duration_ms": 0.78,
  "siem_event": {
    "event_id": "97e6bf2a-4db1-455b-866d-cb5c8a4eb0fa",
    "timestamp": "2026-11-08T10:35:01.124580+00:00",
    "caller_account": "svc-group-viewer-agent",
    "client_ip": "127.0.0.1",
    "command": "list_group_members",
    "outcome": "AUTH_FAILED",
    "status_code": "AUTHENTICATION_FAILED",
    "severity": 8
  }
}
```

#### 2. Console Standard Output / Daemon Log (`journalctl -u ad-proxy`)
```text
2026-11-08 10:35:01 [INFO] [ad_proxy.auth] Authenticating service account 'svc-group-viewer-agent' against Domain Controllers over LDAPS...
2026-11-08 10:35:01 [WARNING] [ad_proxy.auth] Authentication failed for 'svc-group-viewer-agent': Invalid Active Directory credentials (bad password).
[AUDIT-SIEM] {"@timestamp":"2026-11-08T10:35:01.124580+00:00","event":{"id":"97e6bf2a-4db1-455b-866d-cb5c8a4eb0fa","category":["iam","network"],"type":["access","denial"],"action":"ad_proxy.list_group_members","outcome":"failure","severity":8,"reason":"Agent credential bind to Active Directory failed: Invalid Active Directory credentials (bad password)."},"source":{"ip":"127.0.0.1"},"user":{"name":"svc-group-viewer-agent","domain":"corp.acme.internal"},"active_directory":{"command":"list_group_members","status_code":"AUTHENTICATION_FAILED","target_dn":"VPN-Users","parameters":{"caller":"svc-group-viewer-agent"}},"service":{"name":"ad-ldaps-proxy","version":"1.0.0"}}
```

#### 3. SIEM Audit Log Record (`logs/audit.log` — Elastic Common Schema JSON)
```json
{
  "@timestamp": "2026-11-08T10:35:01.124580+00:00",
  "event": {
    "id": "97e6bf2a-4db1-455b-866d-cb5c8a4eb0fa",
    "category": ["iam", "network"],
    "type": ["access", "denial"],
    "action": "ad_proxy.list_group_members",
    "outcome": "failure",
    "severity": 8,
    "duration": 780000,
    "reason": "Agent credential bind to Active Directory failed: Invalid Active Directory credentials (bad password)."
  },
  "source": { "ip": "127.0.0.1" },
  "user": {
    "name": "svc-group-viewer-agent",
    "domain": "corp.acme.internal"
  },
  "active_directory": {
    "command": "list_group_members",
    "status_code": "AUTHENTICATION_FAILED",
    "target_dn": "VPN-Users",
    "parameters": { "caller": "svc-group-viewer-agent" }
  },
  "service": { "name": "ad-ldaps-proxy", "version": "1.0.0" }
}
```

#### 4. Wazuh Alert Record (`logs/wazuh_alerts.json`)
```json
{
  "timestamp": "2026-11-08T10:35:01.124580+00:00",
  "rule": {
    "id": 100102,
    "level": 7,
    "description": "Active Directory LDAPS Proxy: Authentication Failure",
    "groups": ["ad_proxy", "authentication_failure"]
  },
  "agent": { "id": "000", "name": "ad-proxy-gateway", "ip": "127.0.0.1" },
  "manager": { "name": "wazuh-manager" },
  "decoder": { "name": "ad_proxy_json" },
  "data": {
    "ad_proxy": {
      "event_id": "97e6bf2a-4db1-455b-866d-cb5c8a4eb0fa",
      "caller_account": "svc-group-viewer-agent",
      "command": "list_group_members",
      "status_code": "AUTHENTICATION_FAILED",
      "severity": 8,
      "domain": "corp.acme.internal"
    }
  },
  "location": "active_directory_proxy",
  "full_log": "Agent credential bind to Active Directory failed: Invalid Active Directory credentials (bad password)."
}
```

---

## Step 4: Test Phase 2 — Authenticating with CORRECT Password but FORBIDDEN Request

In this phase, the AI agent provides its **correct password** (`GroupViewerSecret2026!`), but requests an unauthorized command, such as `search_users` (or `disable_account`), which is outside its permitted scope.

### Phase 2: Execution Methods

#### Method 1: Using cURL
```bash
curl -s -X POST http://localhost:3000/api/proxy/execute \
  -H "Content-Type: application/json" \
  -d '{
    "caller_account": "svc-group-viewer-agent",
    "caller_password": "GroupViewerSecret2026!",
    "command": "search_users",
    "parameters": {
      "query": "alex"
    }
  }' | jq .
```

#### Method 2: Using Python Script
```python
req = ProxyRequest(
    caller_account="svc-group-viewer-agent",
    caller_password="GroupViewerSecret2026!",
    command="search_users",
    parameters={"query": "alex"},
)
res = engine.process_request(req)
print(f"Success: {res.success}")
print(f"Status Code: {res.status_code}")
print(f"Message: {res.message}")
```

#### Method 3: Using Web Console Agent Simulator
1. In the **Agent Simulator**, select Preset **"8. Test Step 2: Forbidden Command"**.
2. Click **"Execute LDAPS Proxy Request"**.

---

### Phase 2: Expected Response Payload & Log Outputs

#### 1. HTTP JSON API Response
```json
{
  "success": false,
  "status_code": "FORBIDDEN",
  "message": "Access Denied: Command 'search_users' is explicitly denied for service account 'svc-group-viewer-agent'.",
  "data": null,
  "request_id": "f5127e33-728b-4b19-b68a-aa2df7894a02",
  "duration_ms": 0.81,
  "siem_event": {
    "event_id": "f5127e33-728b-4b19-b68a-aa2df7894a02",
    "caller_account": "svc-group-viewer-agent",
    "command": "search_users",
    "outcome": "FORBIDDEN_COMMAND",
    "status_code": "FORBIDDEN",
    "severity": 7
  }
}
```

#### 2. Console Standard Output / Daemon Log
```text
2026-11-08 10:35:12 [INFO] [ad_proxy.auth] Authenticating service account 'svc-group-viewer-agent' against Domain Controllers over LDAPS...
2026-11-08 10:35:12 [INFO] [ad_proxy.auth] Authentication succeeded for 'svc-group-viewer-agent'.
2026-11-08 10:35:12 [WARNING] [ad_proxy.rbac] Access Denied: Command 'search_users' explicitly blacklisted for account 'svc-group-viewer-agent'.
[AUDIT-SIEM] {"@timestamp":"2026-11-08T10:35:12.654321+00:00","event":{"id":"f5127e33-728b-4b19-b68a-aa2df7894a02","category":["iam","network"],"type":["access","denial"],"action":"ad_proxy.search_users","outcome":"failure","severity":7,"reason":"Command 'search_users' is explicitly denied for service account 'svc-group-viewer-agent'."},"source":{"ip":"127.0.0.1"},"user":{"name":"svc-group-viewer-agent","domain":"corp.acme.internal"},"active_directory":{"command":"search_users","status_code":"FORBIDDEN","parameters":{"query":"alex"}},"service":{"name":"ad-ldaps-proxy","version":"1.0.0"}}
```

#### 3. SIEM Audit Log Record (`logs/audit.log` — ECS JSON)
```json
{
  "@timestamp": "2026-11-08T10:35:12.654321+00:00",
  "event": {
    "id": "f5127e33-728b-4b19-b68a-aa2df7894a02",
    "category": ["iam", "network"],
    "type": ["access", "denial"],
    "action": "ad_proxy.search_users",
    "outcome": "failure",
    "severity": 7,
    "duration": 810000,
    "reason": "Command 'search_users' is explicitly denied for service account 'svc-group-viewer-agent'."
  },
  "source": { "ip": "127.0.0.1" },
  "user": {
    "name": "svc-group-viewer-agent",
    "domain": "corp.acme.internal"
  },
  "active_directory": {
    "command": "search_users",
    "status_code": "FORBIDDEN",
    "parameters": { "query": "alex" }
  },
  "service": { "name": "ad-ldaps-proxy", "version": "1.0.0" }
}
```

---

### Phase 2 (Variant): Critical Tier-0 Escalation Attempt

If the agent attempts to target a **Tier-0 group** (such as `Domain Admins`), the proxy intercepts it as a high-severity threat:

```bash
curl -s -X POST http://localhost:3000/api/proxy/execute \
  -H "Content-Type: application/json" \
  -d '{
    "caller_account": "svc-group-viewer-agent",
    "caller_password": "GroupViewerSecret2026!",
    "command": "list_group_members",
    "parameters": {
      "group_name": "Domain Admins"
    }
  }' | jq .
```

**Output in Logs:**
```text
2026-11-08 10:35:15 [ERROR] [ad_proxy.rbac] SECURITY ALERT [ROGUE AGENT]: Account 'svc-group-viewer-agent' attempted unsanctioned operation 'list_group_members' on critical Tier-0 group 'Domain Admins'.
2026-11-08 10:35:15 [CRITICAL] [ad_proxy.siem] [CRITICAL SECURITY ALERT - ROGUE AGENT DETECTED] Rule: 'ROGUE_AGENT_CRITICAL_GROUP_TARGET' | Severity: 10
```

---

## Step 5: Test Phase 3 — Authenticating with CORRECT Password and ALLOWED Request

In this phase, the AI agent provides its **correct password** (`GroupViewerSecret2026!`) and requests an authorized command: `list_group_members` on an approved group (`VPN-Users`).

### Phase 3: Execution Methods

#### Method 1: Using cURL
```bash
curl -s -X POST http://localhost:3000/api/proxy/execute \
  -H "Content-Type: application/json" \
  -d '{
    "caller_account": "svc-group-viewer-agent",
    "caller_password": "GroupViewerSecret2026!",
    "command": "list_group_members",
    "parameters": {
      "group_name": "VPN-Users"
    }
  }' | jq .
```

#### Method 2: Using Python Script
```python
req = ProxyRequest(
    caller_account="svc-group-viewer-agent",
    caller_password="GroupViewerSecret2026!",
    command="list_group_members",
    parameters={"group_name": "VPN-Users"},
)
res = engine.process_request(req)
print(f"Success: {res.success}")
print(f"Status Code: {res.status_code}")
print(f"Total Members Retrieved: {len(res.data)}")
for member in res.data:
    print(f" - {member.get('displayName')} ({member.get('mail')})")
```

#### Method 3: Using Web Console Agent Simulator
1. In the **Agent Simulator**, select Preset **"9. Test Step 3: Allowed Group View"**.
2. Click **"Execute LDAPS Proxy Request"**.

---

### Phase 3: Expected Response Payload & Log Outputs

#### 1. HTTP JSON API Response
```json
{
  "success": true,
  "status_code": "SUCCESS",
  "message": "LDAPS request executed successfully.",
  "data": [
    {
      "sAMAccountName": "alex.rivera",
      "userPrincipalName": "alex.rivera@corp.acme.internal",
      "displayName": "Alex Rivera",
      "mail": "alex.rivera@corp.acme.internal",
      "department": "Engineering",
      "title": "Senior Cloud Architect",
      "distinguishedName": "CN=Alex Rivera,OU=Engineers,OU=Users,DC=corp,DC=acme,DC=internal",
      "userAccountControl": 512
    }
  ],
  "request_id": "c194e82b-5813-40f4-a09c-73ec56d91244",
  "duration_ms": 0.45,
  "siem_event": {
    "event_id": "c194e82b-5813-40f4-a09c-73ec56d91244",
    "timestamp": "2026-11-08T10:35:25.109823+00:00",
    "caller_account": "svc-group-viewer-agent",
    "client_ip": "127.0.0.1",
    "command": "list_group_members",
    "target_dn": "VPN-Users",
    "outcome": "SUCCESS",
    "status_code": "SUCCESS",
    "severity": 3
  }
}
```

#### 2. Console Standard Output / Daemon Log
```text
2026-11-08 10:35:25 [INFO] [ad_proxy.auth] Authenticating service account 'svc-group-viewer-agent' against Domain Controllers over LDAPS...
2026-11-08 10:35:25 [INFO] [ad_proxy.auth] Authentication succeeded for 'svc-group-viewer-agent'.
2026-11-08 10:35:25 [INFO] [ad_proxy.rbac] Access Granted: Account 'svc-group-viewer-agent' authorized for command 'list_group_members'.
[AUDIT-SIEM] {"@timestamp":"2026-11-08T10:35:25.109823+00:00","event":{"id":"c194e82b-5813-40f4-a09c-73ec56d91244","category":["iam","network"],"type":["access","protocol"],"action":"ad_proxy.list_group_members","outcome":"success","severity":3,"duration":450000,"reason":"Executed Active Directory LDAPS command 'list_group_members' successfully."},"source":{"ip":"127.0.0.1"},"user":{"name":"svc-group-viewer-agent","domain":"corp.acme.internal"},"active_directory":{"command":"list_group_members","status_code":"SUCCESS","target_dn":"VPN-Users","parameters":{"group_name":"VPN-Users"}},"service":{"name":"ad-ldaps-proxy","version":"1.0.0"}}
```

#### 3. Splunk HEC SIEM Record (Dispatched over HTTP to Splunk Collector)
```json
{
  "time": 1794134125.109,
  "host": "ad-proxy.corp.acme.internal",
  "source": "ad-ldaps-proxy",
  "sourcetype": "active_directory:proxy:audit",
  "index": "active_directory",
  "event": {
    "event_id": "c194e82b-5813-40f4-a09c-73ec56d91244",
    "timestamp": "2026-11-08T10:35:25.109823+00:00",
    "caller_account": "svc-group-viewer-agent",
    "client_ip": "127.0.0.1",
    "command": "list_group_members",
    "target_dn": "VPN-Users",
    "outcome": "SUCCESS",
    "status_code": "SUCCESS",
    "severity": 3,
    "duration_ms": 0.45,
    "domain": "corp.acme.internal",
    "parameters": {
      "group_name": "VPN-Users"
    }
  }
}
```

#### 4. Wazuh Alert Record (`logs/wazuh_alerts.json`)
```json
{
  "timestamp": "2026-11-08T10:35:25.109823+00:00",
  "rule": {
    "id": 100100,
    "level": 3,
    "description": "Active Directory LDAPS Proxy: Successful Query",
    "groups": ["ad_proxy", "directory_query"]
  },
  "agent": { "id": "000", "name": "ad-proxy-gateway", "ip": "127.0.0.1" },
  "manager": { "name": "wazuh-manager" },
  "decoder": { "name": "ad_proxy_json" },
  "data": {
    "ad_proxy": {
      "event_id": "c194e82b-5813-40f4-a09c-73ec56d91244",
      "caller_account": "svc-group-viewer-agent",
      "command": "list_group_members",
      "target_dn": "VPN-Users",
      "status_code": "SUCCESS",
      "severity": 3,
      "domain": "corp.acme.internal"
    }
  },
  "location": "active_directory_proxy",
  "full_log": "Executed Active Directory LDAPS command 'list_group_members' successfully."
}
```

---

## Step 6: Automated Verification via Regression Suite

This complete three-phase functionality procedure is fully integrated into the test harness (`tests/test_proxy.py`):

- `test_16_procedure_step1_wrong_password_authentication_failure`
- `test_17_procedure_step2_correct_password_forbidden_request`
- `test_18_procedure_step3_correct_password_allowed_group_view_request`

To execute all 43 unit, security, and functional tests from the terminal:

```bash
python3 -m ad_proxy.cli --run-tests
```

**Expected Result:**
```text
test_16_procedure_step1_wrong_password_authentication_failure (tests.test_proxy.TestActiveDirectoryProxy) ... ok
test_17_procedure_step2_correct_password_forbidden_request (tests.test_proxy.TestActiveDirectoryProxy) ... ok
test_18_procedure_step3_correct_password_allowed_group_view_request (tests.test_proxy.TestActiveDirectoryProxy) ... ok

----------------------------------------------------------------------
Ran 43 tests in 0.392s

OK
```

In the Web Console:
1. Navigate to the **Verification Tests** tab.
2. Click **"Execute Complete Test Suite (43 Tests)"**.
3. Verify the status banner reports **43 / 43 test assertions passed (100% PASSING)**.

---

## Summary & Verification Matrix

| Test Phase | Calling Identity | Supplied Password | Requested Command | Target Object | Outcome | Status Code | Severity | Primary SIEM Rule / Reason |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Phase 1: Bad Password** | `svc-group-viewer-agent` | `WrongPassword123!` | `list_group_members` | `VPN-Users` | **FAIL** | `AUTHENTICATION_FAILED` | **8** | Invalid Active Directory credentials (bad password) |
| **Phase 2: Forbidden Action** | `svc-group-viewer-agent` | `GroupViewerSecret2026!` | `search_users` | `alex` | **FAIL** | `FORBIDDEN` | **7** | Command 'search_users' is explicitly denied |
| **Phase 2 (Variant): Tier-0 Tamper** | `svc-group-viewer-agent` | `GroupViewerSecret2026!` | `list_group_members` | `Domain Admins` | **FAIL** | `CRITICAL_SECURITY_ALERT` | **10** | `ROGUE_AGENT_CRITICAL_GROUP_TARGET` |
| **Phase 3: Allowed Action** | `svc-group-viewer-agent` | `GroupViewerSecret2026!` | `list_group_members` | `VPN-Users` | **SUCCESS** | `SUCCESS` | **3** | Executed Active Directory LDAPS command successfully |

This test procedure confirms that the Active Directory Secure LDAPS Proxy rigorously enforces zero-trust boundaries: **authentication** is verified first, **RBAC authorization** limits actions strictly to permitted commands, sensitive attributes and protected objects are shielded, and **structured SIEM audit events** are recorded for every transaction.
