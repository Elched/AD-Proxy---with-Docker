import React, { useState } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Send,
  Lock,
  RefreshCw,
  Copy,
  Check,
  Zap
} from 'lucide-react';
import { CommandMeta, ProxyExecutionResult } from '../types';

interface AgentSimulatorProps {
  commands: CommandMeta[];
  onExecutionCompleted?: () => void;
}

const PRESET_ACCOUNTS = [
  {
    id: 'ai-triage-agent',
    label: 'ai-triage-agent (SOC Incident Response)',
    defaultPassword: 'AgentSecurePassword2026!',
    description: 'Permitted: read directory, inspect users/groups, quarantine/disable accounts.',
  },
  {
    id: 'svc-it-helpdesk-agent',
    label: 'svc-it-helpdesk-agent (Helpdesk Bot)',
    defaultPassword: 'HelpdeskSecretToken2026#',
    description: 'Permitted: unlock accounts, manage VPN-Users group (requires ticket ID).',
  },
  {
    id: 'svc-compliance-scanner',
    label: 'svc-compliance-scanner (Audit Scanner)',
    defaultPassword: 'StandardUserPass1!',
    description: 'Permitted: read-only directory enumeration.',
  },
  {
    id: 'svc-group-viewer-agent',
    label: 'svc-group-viewer-agent (Group Member Viewer)',
    defaultPassword: 'GroupViewerSecret2026!',
    description: 'Permitted ONLY: list_group_members (e.g. VPN-Users, Developers).',
  },
  {
    id: 'unauthorized-agent',
    label: 'unauthorized-agent (Unregistered Rogue Account)',
    defaultPassword: 'WrongPassword999!',
    description: 'Not in allowlist: Will be blocked with 403 Forbidden.',
  },
];

interface ScenarioPreset {
  id: string;
  label: string;
  tone: 'emerald' | 'amber' | 'rose';
  caller: string;
  password: string;
  command: string;
  ticketId: string;
  parameters: Record<string, any>;
}

const SCENARIO_PRESETS: ScenarioPreset[] = [
  {
    id: 'sanctioned-read',
    label: '1. Sanctioned Group Read',
    tone: 'emerald',
    caller: 'ai-triage-agent',
    password: 'AgentSecurePassword2026!',
    command: 'list_group_members',
    ticketId: 'INC-2026-8819',
    parameters: { group_name: 'VPN-Users', recursive: false },
  },
  {
    id: 'sanctioned-write',
    label: '2. Helpdesk VPN Add + Ticket',
    tone: 'emerald',
    caller: 'svc-it-helpdesk-agent',
    password: 'HelpdeskSecretToken2026#',
    command: 'add_user_to_group',
    ticketId: 'CHG-2026-4410',
    parameters: { user_identifier: 'sarah.chen', group_name: 'VPN-Users' },
  },
  {
    id: 'missing-ticket',
    label: '3. Missing Ticket Block',
    tone: 'amber',
    caller: 'ai-triage-agent',
    password: 'AgentSecurePassword2026!',
    command: 'disable_account',
    ticketId: '',
    parameters: { user_identifier: 'alex.rivera', reason: 'Quarantine' },
  },
  {
    id: 'bad-password',
    label: '4. Invalid AD Password',
    tone: 'amber',
    caller: 'ai-triage-agent',
    password: 'WrongPassword123!',
    command: 'get_domain_info',
    ticketId: '',
    parameters: {},
  },
  {
    id: 'rogue-admin-reset',
    label: '5. Rogue Admin Reset (Sev 10)',
    tone: 'rose',
    caller: 'ai-triage-agent',
    password: 'AgentSecurePassword2026!',
    command: 'reset_password',
    ticketId: 'INC-2026-9999',
    parameters: { user_identifier: 'administrator', new_password: 'CompromisedPass123!' },
  },
  {
    id: 'rogue-tier0-group',
    label: '6. Tier-0 Group Tamper (Sev 10)',
    tone: 'rose',
    caller: 'svc-it-helpdesk-agent',
    password: 'HelpdeskSecretToken2026#',
    command: 'add_user_to_group',
    ticketId: 'INC-2026-9999',
    parameters: { user_identifier: 'alex.rivera', group_name: 'Domain Admins' },
  },
  {
    id: 'proc-step1-wrong-pwd',
    label: '7. Test Step 1: Wrong Password',
    tone: 'amber',
    caller: 'svc-group-viewer-agent',
    password: 'WrongPassword123!',
    command: 'list_group_members',
    ticketId: '',
    parameters: { group_name: 'VPN-Users' },
  },
  {
    id: 'proc-step2-forbidden-req',
    label: '8. Test Step 2: Forbidden Command',
    tone: 'amber',
    caller: 'svc-group-viewer-agent',
    password: 'GroupViewerSecret2026!',
    command: 'search_users',
    ticketId: '',
    parameters: { query: 'alex' },
  },
  {
    id: 'proc-step3-allowed-req',
    label: '9. Test Step 3: Allowed Group View',
    tone: 'emerald',
    caller: 'svc-group-viewer-agent',
    password: 'GroupViewerSecret2026!',
    command: 'list_group_members',
    ticketId: '',
    parameters: { group_name: 'VPN-Users' },
  },
];

/**
 * Interactive AI Agent LDAPS Query Simulator.
 * Allows testing sanctioned operations, RBAC policy blocks, and Rogue Agent heuristics.
 */
export const AgentSimulator: React.FC<AgentSimulatorProps> = ({
  commands,
  onExecutionCompleted,
}) => {
  const [callerAccount, setCallerAccount] = useState('ai-triage-agent');
  const [password, setPassword] = useState('AgentSecurePassword2026!');
  const [selectedCommand, setSelectedCommand] = useState('list_group_members');
  const [ticketId, setTicketId] = useState('INC-2026-8819');
  const [parameters, setParameters] = useState<Record<string, any>>({
    group_name: 'VPN-Users',
    recursive: false,
  });

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProxyExecutionResult | null>(null);
  const [copied, setCopied] = useState(false);

  const applyScenario = (preset: ScenarioPreset) => {
    setCallerAccount(preset.caller);
    setPassword(preset.password);
    setSelectedCommand(preset.command);
    setTicketId(preset.ticketId);
    setParameters({ ...preset.parameters });
  };

  const handleAccountChange = (accId: string) => {
    setCallerAccount(accId);
    const found = PRESET_ACCOUNTS.find((a) => a.id === accId);
    if (found) {
      setPassword(found.defaultPassword);
    }
  };

  const handleCommandChange = (cmdName: string) => {
    setSelectedCommand(cmdName);
    const cmd = commands.find((c) => c.name === cmdName);
    if (!cmd) return;

    const defaults: Record<string, Record<string, any>> = {
      list_group_members: { group_name: 'VPN-Users', recursive: false },
      search_users: { query: 'Rivera', department: 'Engineering', enabled_only: false },
      get_user_attributes: { user_identifier: 'alex.rivera' },
      check_user_membership: { user_identifier: 'alex.rivera', group_name: 'VPN-Users' },
      add_user_to_group: { user_identifier: 'sarah.chen', group_name: 'VPN-Users' },
      remove_user_from_group: { user_identifier: 'sarah.chen', group_name: 'VPN-Users' },
      disable_account: { user_identifier: 'alex.rivera', reason: 'Security Quarantine' },
      enable_account: { user_identifier: 'compromised.contractor' },
      unlock_account: { user_identifier: 'alex.rivera' },
      reset_password: { user_identifier: 'alex.rivera', new_password: 'ComplexSecretPassword2026!' },
      get_domain_info: {},
    };

    if (defaults[cmdName]) {
      setParameters(defaults[cmdName]);
    } else {
      const initial: Record<string, any> = {};
      cmd.required_params.forEach((p) => {
        initial[p] = p.includes('group') ? 'VPN-Users' : p.includes('user') ? 'alex.rivera' : 'test';
      });
      setParameters(initial);
    }
  };

  const handleExecute = async () => {
    setLoading(true);
    setResult(null);

    try {
      const res = await fetch('/api/proxy/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caller_account: callerAccount,
          caller_password: password,
          command: selectedCommand,
          parameters,
          ticket_id: ticketId || null,
        }),
      });

      const data = await res.json();
      setResult(data);
      if (onExecutionCompleted) {
        onExecutionCompleted();
      }
    } catch (err: any) {
      setResult({
        success: false,
        status_code: 'CLIENT_ERROR',
        message: err.message || 'Network request failed',
      });
    } finally {
      setLoading(false);
    }
  };

  const copyResultJson = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const activeCmdMeta = commands.find((c) => c.name === selectedCommand);

  return (
    <div className="space-y-5">
      {/* 1-Click Scenario Presets Bar */}
      <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/80 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 shrink-0">
          <Zap className="w-3.5 h-3.5 text-emerald-400" />
          <span>1-Click Test Scenarios:</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {SCENARIO_PRESETS.map((preset) => {
            const toneStyle =
              preset.tone === 'emerald'
                ? 'border-emerald-800/80 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50'
                : preset.tone === 'amber'
                ? 'border-amber-800/80 bg-amber-950/40 text-amber-300 hover:bg-amber-900/50'
                : 'border-rose-800/80 bg-rose-950/50 text-rose-300 hover:bg-rose-900/60';
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => applyScenario(preset)}
                className={`px-2.5 py-1 rounded border text-[11px] font-medium transition-colors cursor-pointer ${toneStyle}`}
              >
                {preset.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: AI Agent Query Configuration Form */}
        <div className="lg:col-span-6 space-y-5">
          <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
              <div>
                <h2 className="text-base font-semibold text-white">AI Agent Query Simulator</h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Configure credentials, command, and parameters or pick a 1-click scenario above.
                </p>
              </div>
              <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-mono shrink-0">
                <Lock className="w-3.5 h-3.5" />
                <span>LDAPS TLS 1.2+</span>
              </div>
            </div>

            <div className="space-y-4 text-xs">
              {/* 1. Service Account Selector */}
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Calling Service Account (AI Agent Identity)
                </label>
                <select
                  value={callerAccount}
                  onChange={(e) => handleAccountChange(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 focus:outline-none focus:border-emerald-500"
                >
                  {PRESET_ACCOUNTS.map((acc) => (
                    <option key={acc.id} value={acc.id}>
                      {acc.label}
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-slate-400 mt-1">
                  {PRESET_ACCOUNTS.find((a) => a.id === callerAccount)?.description}
                </p>
              </div>

              {/* 2. AD Credentials */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    AD Password (Bound to DC)
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                    placeholder="Enter AD service account password"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">
                    IT Approval Ticket ID (Mandatory for Writes)
                  </label>
                  <input
                    type="text"
                    value={ticketId}
                    onChange={(e) => setTicketId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                    placeholder="e.g. INC-2026-8819 or CHG-9901"
                  />
                </div>
              </div>

              {/* 3. Command Selector */}
              <div className="pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-slate-300 font-medium">
                    Active Directory LDAPS Command
                  </label>
                  {activeCmdMeta && (
                    <span
                      className={`text-[11px] font-mono font-semibold ${
                        activeCmdMeta.risk_level === 'LOW'
                          ? 'text-emerald-400'
                          : activeCmdMeta.risk_level === 'MEDIUM'
                          ? 'text-blue-400'
                          : activeCmdMeta.risk_level === 'HIGH'
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }`}
                    >
                      Risk: {activeCmdMeta.risk_level}
                    </span>
                  )}
                </div>

                <select
                  value={selectedCommand}
                  onChange={(e) => handleCommandChange(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                >
                  {commands.map((cmd) => (
                    <option key={cmd.name} value={cmd.name}>
                      {cmd.name} ({cmd.category}) - {cmd.description}
                    </option>
                  ))}
                </select>
              </div>

              {/* 4. Dynamic Parameter Inputs */}
              <div className="space-y-3 p-3.5 rounded-md bg-slate-950/80 border border-slate-800/80">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-300">
                    Command Parameters (RFC 4515 Escaped)
                  </span>
                  {parameters.group_name && (
                    <button
                      type="button"
                      onClick={() => setParameters({ ...parameters, group_name: 'Domain Admins' })}
                      className="text-[11px] text-rose-400 hover:text-rose-300 underline cursor-pointer"
                    >
                      Target "Domain Admins"
                    </button>
                  )}
                </div>

                {Object.keys(parameters).length === 0 ? (
                  <p className="text-[11px] text-slate-500 italic">No parameters required for this command.</p>
                ) : (
                  Object.entries(parameters).map(([key, val]) => (
                    <div key={key} className="space-y-1">
                      <label className="text-[11px] text-slate-400 font-mono flex items-center justify-between">
                        <span>{key}</span>
                        {activeCmdMeta?.required_params.includes(key) && (
                          <span className="text-amber-400 text-[10px]">required</span>
                        )}
                      </label>
                      {typeof val === 'boolean' ? (
                        <select
                          value={val ? 'true' : 'false'}
                          onChange={(e) =>
                            setParameters({ ...parameters, [key]: e.target.value === 'true' })
                          }
                          className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-100 text-xs"
                        >
                          <option value="false">false</option>
                          <option value="true">true</option>
                        </select>
                      ) : (
                        <input
                          type="text"
                          value={String(val)}
                          onChange={(e) => setParameters({ ...parameters, [key]: e.target.value })}
                          className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                        />
                      )}
                    </div>
                  ))
                )}
              </div>

              {/* Execute Button */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={handleExecute}
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-md font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 transition-colors disabled:opacity-50 text-xs cursor-pointer"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Processing Secure LDAPS Pipeline...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-3.5 h-3.5" />
                      <span>Dispatch LDAPS Request Through AD-Proxy</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: 5-Stage Zero-Trust Verification Pipeline & Result */}
        <div className="lg:col-span-6 space-y-5">
          {/* Pipeline Stage Visualizer */}
          <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
              <h3 className="text-base font-semibold text-white">5-Stage Verification Pipeline</h3>
              <span className="text-xs text-slate-400">Zero-Trust Inspection</span>
            </div>

            <div className="space-y-3">
              {/* Stage 1 */}
              <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
                <div className="mt-0.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="flex-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">1. LDAPS Mutual TLS Handshake</span>
                    <span className="text-[11px] font-mono text-slate-400">TLS 1.2+ / Port 10636</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Secure socket established. Client payload encrypted; plain-text LDAP strictly prohibited.
                  </p>
                </div>
              </div>

              {/* Stage 2 */}
              <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
                <div className="mt-0.5">
                  {result ? (
                    result.status_code === 'AUTHENTICATION_FAILED' ? (
                      <XCircle className="w-4 h-4 text-rose-400" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    )
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-600" />
                  )}
                </div>
                <div className="flex-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">2. AD Domain Controller Credential Bind</span>
                    {result && (
                      <span
                        className={`text-[11px] font-mono ${
                          result.status_code === 'AUTHENTICATION_FAILED' ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                      >
                        {result.status_code === 'AUTHENTICATION_FAILED' ? 'FAILED' : 'VERIFIED'}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Proxy verifies agent identity against Domain Controllers via secure LDAPS simple bind.
                  </p>
                </div>
              </div>

              {/* Stage 3 */}
              <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
                <div className="mt-0.5">
                  {result ? (
                    result.status_code === 'CRITICAL_SECURITY_ALERT' ? (
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                    ) : result.status_code === 'FORBIDDEN' || result.status_code === 'INVALID_INPUT' ? (
                      <XCircle className="w-4 h-4 text-rose-400" />
                    ) : result.success ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-600" />
                    )
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-600" />
                  )}
                </div>
                <div className="flex-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">3. Granular RBAC & Rogue Agent Interceptor</span>
                    {result && (
                      <span
                        className={`text-[11px] font-mono font-bold ${
                          result.status_code === 'CRITICAL_SECURITY_ALERT' || result.status_code === 'FORBIDDEN'
                            ? 'text-rose-400'
                            : result.success
                            ? 'text-emerald-400'
                            : 'text-slate-400'
                        }`}
                      >
                        {result.status_code === 'CRITICAL_SECURITY_ALERT'
                          ? 'ROGUE AGENT DETECTED (SEV 10)'
                          : result.status_code === 'FORBIDDEN'
                          ? 'DENIED'
                          : result.success
                          ? 'PASSED'
                          : 'SKIPPED'}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Evaluates RBAC and intercepts rogue or hallucinating agents targeting Tier-0 groups or admins.
                  </p>
                </div>
              </div>

              {/* Stage 4 */}
              <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
                <div className="mt-0.5">
                  {result ? (
                    result.success ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-600" />
                    )
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-600" />
                  )}
                </div>
                <div className="flex-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">4. Upstream Query to Domain Controllers</span>
                    {result?.success && (
                      <span className="text-[11px] font-mono tabular-nums text-emerald-400">
                        {result.duration_ms?.toFixed(2)} ms
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Query dispatched via gMSA / OpenBao injected credentials over LDAPS. Results sanitized.
                  </p>
                </div>
              </div>

              {/* Stage 5 */}
              <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
                <div className="mt-0.5">
                  {result?.siem_event ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-600" />
                  )}
                </div>
                <div className="flex-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">5. SIEM Audit Logging (CEF / ECS)</span>
                    {result?.siem_event && (
                      <span className="text-[11px] font-mono text-emerald-400">LOGGED</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Audit event streamed to local file, syslog, or SIEM webhook with complete compliance metadata.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Query Response & Audit Preview */}
          <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
              <h3 className="text-base font-semibold text-white">Proxy Execution Response</h3>
              {result && (
                <div className="flex items-center gap-3">
                  <span
                    className={`text-xs font-mono font-bold ${
                      result.success ? 'text-emerald-400' : 'text-rose-400'
                    }`}
                  >
                    {result.status_code}
                  </span>
                  <button
                    onClick={copyResultJson}
                    className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              )}
            </div>

            {!result ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                Select a 1-click scenario above or configure parameters on the left to test the Zero-Trust LDAPS pipeline.
              </div>
            ) : (
              <div className="space-y-3">
                {/* Status Banner */}
                <div
                  className={`p-3 rounded border text-xs flex items-start gap-2.5 ${
                    result.success
                      ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
                      : result.status_code === 'CRITICAL_SECURITY_ALERT'
                      ? 'bg-rose-950/70 border-rose-600 text-rose-100'
                      : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
                  }`}
                >
                  {result.success ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <div className="font-semibold flex items-center justify-between gap-2">
                      <span>{result.message}</span>
                      {result.status_code === 'CRITICAL_SECURITY_ALERT' && (
                        <span className="font-mono text-[10px] text-rose-300 font-bold shrink-0">
                          SEVERITY 10 / CRITICAL
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Request ID: <span className="font-mono">{result.request_id}</span> · Latency:{' '}
                      <span className="font-mono tabular-nums">{result.duration_ms?.toFixed(2)} ms</span>
                    </div>
                    {result.status_code === 'CRITICAL_SECURITY_ALERT' && (
                      <div className="mt-2 p-2 rounded bg-rose-950/80 border border-rose-800 text-[11px] text-rose-200 leading-relaxed">
                        <strong className="text-white">Threat Mitigation:</strong> Rogue/hallucinating AI agent activity
                        intercepted. Connection terminated immediately. Threat indicator{' '}
                        <code className="bg-slate-950 px-1 py-0.5 rounded text-rose-300">
                          ROGUE_OR_HALLUCINATING_AGENT_DETECTED
                        </code>{' '}
                        dispatched to SIEM and SOC alarms.
                      </div>
                    )}
                  </div>
                </div>

                {/* Data payload if success */}
                {result.data && (
                  <div>
                    <div className="text-[11px] font-semibold text-slate-400 mb-1">
                      Returned Active Directory Data:
                    </div>
                    <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-48">
                      {JSON.stringify(result.data, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Emitted SIEM Event */}
                {result.siem_event && (
                  <div>
                    <div className="text-[11px] font-semibold text-slate-400 mb-1 flex items-center justify-between">
                      <span>Generated SIEM Audit Record:</span>
                      <span className="text-slate-500 font-mono">Format: ECS JSON</span>
                    </div>
                    <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300 overflow-x-auto max-h-40">
                      {JSON.stringify(result.siem_event, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
