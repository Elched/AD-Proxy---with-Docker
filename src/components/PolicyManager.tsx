import React, { useState, useEffect } from 'react';
import {
  FileCode,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Save,
  Key,
  Database,
  Lock,
  Sliders,
  Check
} from 'lucide-react';
import { ParsedProxyConfig } from '../types';

interface PolicyManagerProps {
  onConfigUpdated?: () => void;
}

/**
 * RBAC Policy & YAML Configuration Manager.
 * Dynamically renders the parsed Active Directory configuration and provides
 * 1-click configuration helpers alongside a full YAML editor with dry-run validation.
 */
export const PolicyManager: React.FC<PolicyManagerProps> = ({ onConfigUpdated }) => {
  const [yamlContent, setYamlContent] = useState('');
  const [parsedConfig, setParsedConfig] = useState<ParsedProxyConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ text: string; isError?: boolean } | null>(null);
  const [checkOutput, setCheckOutput] = useState('');
  const [activeSubTab, setActiveSubTab] = useState<'matrix' | 'editor'>('matrix');

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/proxy/config');
      const data = await res.json();
      setYamlContent(data.raw_yaml || '');
      setCheckOutput(data.check_output || '');
      if (data.parsed_config) {
        setParsedConfig(data.parsed_config);
      }
    } catch (err: any) {
      setStatusMessage({ text: 'Failed to load configuration: ' + err.message, isError: true });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const submitConfig = async (validateOnly: boolean) => {
    if (validateOnly) {
      setValidating(true);
    } else {
      setSaving(true);
    }
    setStatusMessage(null);

    try {
      const res = await fetch('/api/proxy/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml_content: yamlContent, validate_only: validateOnly }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatusMessage({ text: data.error + (data.details ? `: ${data.details}` : ''), isError: true });
      } else {
        setStatusMessage({ text: data.message, isError: false });
        if (data.output) setCheckOutput(data.output);
        if (data.parsed_config) setParsedConfig(data.parsed_config);
        if (!validateOnly && onConfigUpdated) onConfigUpdated();
      }
    } catch (err: any) {
      setStatusMessage({ text: 'Error processing configuration: ' + err.message, isError: true });
    } finally {
      setValidating(false);
      setSaving(false);
    }
  };

  // Helper to quickly toggle YAML fields without manual searching
  const applyQuickSetting = (
    type: 'auth_openbao' | 'auth_gmsa' | 'auth_env' | 'siem_ecs' | 'siem_cef' | 'siem_splunk' | 'siem_wazuh'
  ) => {
    let updated = yamlContent;
    if (type === 'auth_openbao') {
      updated = updated
        .replace(/mode:\s*"(gmsa|service_account)"/, 'mode: "service_account"')
        .replace(/secret_provider:\s*"(env|openbao|vault|none)"/, 'secret_provider: "openbao"');
    } else if (type === 'auth_gmsa') {
      updated = updated
        .replace(/mode:\s*"(gmsa|service_account)"/, 'mode: "gmsa"')
        .replace(/secret_provider:\s*"(env|openbao|vault|none)"/, 'secret_provider: "none"');
    } else if (type === 'auth_env') {
      updated = updated
        .replace(/mode:\s*"(gmsa|service_account)"/, 'mode: "service_account"')
        .replace(/secret_provider:\s*"(env|openbao|vault|none)"/, 'secret_provider: "env"');
    } else if (type === 'siem_ecs') {
      updated = updated.replace(/format:\s*"(ecs|cef|splunk_hec|wazuh_json|syslog_rfc5424)"/, 'format: "ecs"');
    } else if (type === 'siem_cef') {
      updated = updated.replace(/format:\s*"(ecs|cef|splunk_hec|wazuh_json|syslog_rfc5424)"/, 'format: "cef"');
    } else if (type === 'siem_splunk') {
      updated = updated.replace(/format:\s*"(ecs|cef|splunk_hec|wazuh_json|syslog_rfc5424)"/, 'format: "splunk_hec"');
      if (!updated.includes('- "splunk"') && !updated.includes("- 'splunk'")) {
        updated = updated.replace(/destinations:\s*\n(\s*-\s*"[^"]+"\s*\n)+/, (match) => {
          return match + '    - "splunk"\n';
        });
      }
    } else if (type === 'siem_wazuh') {
      updated = updated.replace(/format:\s*"(ecs|cef|splunk_hec|wazuh_json|syslog_rfc5424)"/, 'format: "wazuh_json"');
      if (!updated.includes('- "wazuh"') && !updated.includes("- 'wazuh'")) {
        updated = updated.replace(/destinations:\s*\n(\s*-\s*"[^"]+"\s*\n)+/, (match) => {
          return match + '    - "wazuh"\n';
        });
      }
    }
    setYamlContent(updated);
    setStatusMessage({
      text: 'Updated YAML buffer in editor. Click "Validate & Apply" to persist changes.',
      isError: false,
    });
  };

  const domain = parsedConfig?.domain;
  const upstream = parsedConfig?.upstream_auth;
  const siem = parsedConfig?.siem;
  const accounts = parsedConfig?.service_accounts || [];

  return (
    <div className="space-y-6">
      {/* Top Controls & Sub-tabs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
        <div>
          <h2 className="text-base font-semibold text-white">RBAC Policies & Configuration</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Inspect active service account boundaries or customize <code className="text-slate-300">ad_proxy/config.yaml</code> with live schema validation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-md border border-slate-800">
            <button
              onClick={() => setActiveSubTab('matrix')}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeSubTab === 'matrix' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Policy Overview ({accounts.length})
            </button>
            <button
              onClick={() => setActiveSubTab('editor')}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeSubTab === 'editor' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              YAML Editor
            </button>
          </div>

          <button
            onClick={fetchConfig}
            className="p-1.5 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer"
            title="Reload configuration from disk"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {statusMessage && (
        <div
          className={`p-3 rounded border text-xs flex items-center gap-2 ${
            statusMessage.isError
              ? 'bg-rose-950/40 border-rose-800 text-rose-300'
              : 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
          }`}
        >
          {statusMessage.isError ? (
            <AlertTriangle className="w-4 h-4 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {activeSubTab === 'matrix' ? (
        <div className="space-y-6">
          {/* Dynamic Architecture Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-200">
              <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 mb-1">
                <Database className="w-4 h-4" />
                <span>Active Directory Domain</span>
              </div>
              <div className="text-sm font-bold text-white font-mono">
                {domain?.domain_name || 'corp.acme.internal'}
              </div>
              <div className="text-xs text-slate-400 mt-1 font-mono truncate">
                Base DN: {domain?.base_dn || 'DC=corp,DC=acme,DC=internal'}
              </div>
              <div className="text-xs text-slate-500 mt-0.5 tabular-nums">
                DC Pool: {domain?.domain_controllers?.length || 2} hosts · Port: {domain?.ldaps_port || 636} (LDAPS)
              </div>
            </div>

            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-200">
              <div className="flex items-center gap-2 text-xs font-semibold text-blue-400 mb-1">
                <Key className="w-4 h-4" />
                <span>Upstream Authentication</span>
              </div>
              <div className="text-sm font-bold text-white">
                {upstream?.mode === 'gmsa'
                  ? `gMSA (${upstream.gmsa_name || 'svc-adproxy$'})`
                  : `Service Account (${upstream?.secret_provider?.toUpperCase() || 'ENV'})`}
              </div>
              <div className="text-xs text-slate-400 mt-1 truncate">
                Identity: <span className="font-mono">{upstream?.username || upstream?.gmsa_name || 'svc-ad-proxy'}</span>
              </div>
              <div className="text-xs text-slate-500 mt-0.5">
                Zero plaintext credentials stored on disk
              </div>
            </div>

            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-200">
              <div className="flex items-center gap-2 text-xs font-semibold text-amber-400 mb-1">
                <Lock className="w-4 h-4" />
                <span>SIEM & Zero-Trust Guard</span>
              </div>
              <div className="text-sm font-bold text-white">
                Format: {siem?.format?.toUpperCase() || 'ECS'} · Forwarding Active
              </div>
              <div className="text-xs text-slate-400 mt-1 truncate">
                Destinations: <span className="font-mono text-slate-200">{siem?.destinations?.join(', ') || 'file, stdout'}</span>
              </div>
              <div className="text-[11px] text-slate-400 mt-1 space-y-0.5">
                <div>
                  Splunk HEC:{' '}
                  <span className="text-emerald-400 font-mono">
                    {siem?.destinations?.includes('splunk') ? 'Active Forwarder' : 'Configured (Standby)'}
                  </span>
                </div>
                <div>
                  Wazuh XDR:{' '}
                  <span className="text-blue-400 font-mono">
                    {siem?.destinations?.includes('wazuh') ? 'Active Forwarder' : 'Configured (Standby)'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Dynamic Service Accounts RBAC Matrix */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/90 overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">Configured Service Account Allowlist</h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Live RBAC rules parsed from <code className="text-slate-300">ad_proxy/config.yaml</code>
                </p>
              </div>
              <button
                onClick={() => setActiveSubTab('editor')}
                className="text-xs text-emerald-400 hover:text-emerald-300 font-medium cursor-pointer"
              >
                Edit Policies in YAML →
              </button>
            </div>

            <div className="divide-y divide-slate-800 text-xs">
              {accounts.map((acc) => (
                <div key={acc.account_identifier} className="p-5 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-emerald-400 text-sm">
                          {acc.account_identifier}
                        </span>
                        <span className="text-slate-600">·</span>
                        <span className="text-xs text-slate-300">{acc.description}</span>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono text-emerald-400 tabular-nums">
                      {acc.permitted_commands.length} permitted commands
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                    <div>
                      <span className="text-[11px] font-semibold text-slate-400 block mb-1.5">
                        Permitted Commands:
                      </span>
                      <div className="flex flex-wrap gap-1.5 font-mono text-[11px] text-slate-200">
                        {acc.permitted_commands.map((cmd, idx) => (
                          <span key={cmd} className="bg-slate-950 border border-slate-800 px-2 py-0.5 rounded">
                            {cmd}
                            {idx < acc.permitted_commands.length - 1 ? '' : ''}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2">
                      {acc.denied_commands && acc.denied_commands.length > 0 && (
                        <div>
                          <span className="text-[11px] font-semibold text-rose-400 block mb-1">
                            Explicitly Denied Commands:
                          </span>
                          <div className="font-mono text-[11px] text-rose-300">
                            {acc.denied_commands.join(', ')}
                          </div>
                        </div>
                      )}

                      {acc.rules && acc.rules.length > 0 && (
                        <div>
                          <span className="text-[11px] font-semibold text-amber-400 block mb-1">
                            Parameter & Ticket Constraints:
                          </span>
                          <ul className="space-y-1 text-[11px] text-slate-300">
                            {acc.rules.map((r) => (
                              <li key={r.command} className="font-mono">
                                <span className="text-white font-semibold">{r.command}</span>:{' '}
                                {r.require_approval_ticket && (
                                  <span className="text-amber-300">[Ticket Required] </span>
                                )}
                                {r.allowed_groups && r.allowed_groups.length > 0 && (
                                  <span className="text-emerald-300">
                                    AllowedGroups=({r.allowed_groups.join(', ')})
                                  </span>
                                )}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        /* YAML Configuration Editor with 1-Click Helpers */
        <div className="space-y-4">
          {/* Quick Configuration Presets Bar */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/70 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 text-slate-300 font-medium">
              <Sliders className="w-3.5 h-3.5 text-emerald-400" />
              <span>Quick Configuration Presets:</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => applyQuickSetting('auth_openbao')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] cursor-pointer"
              >
                Use OpenBao Vault Auth
              </button>
              <button
                type="button"
                onClick={() => applyQuickSetting('auth_gmsa')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] cursor-pointer"
              >
                Use gMSA Auth
              </button>
              <button
                type="button"
                onClick={() => applyQuickSetting('auth_env')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] cursor-pointer"
              >
                Use Env Var Auth
              </button>
              <span className="text-slate-700">|</span>
              <button
                type="button"
                onClick={() => applyQuickSetting('siem_ecs')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] cursor-pointer"
              >
                SIEM: ECS JSON
              </button>
              <button
                type="button"
                onClick={() => applyQuickSetting('siem_cef')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] cursor-pointer"
              >
                SIEM: ArcSight CEF
              </button>
              <button
                type="button"
                onClick={() => applyQuickSetting('siem_splunk')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-emerald-800/80 text-[11px] cursor-pointer"
              >
                SIEM: Splunk HEC
              </button>
              <button
                type="button"
                onClick={() => applyQuickSetting('siem_wazuh')}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-blue-300 border border-blue-800/80 text-[11px] cursor-pointer"
              >
                SIEM: Wazuh JSON
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2 font-mono text-slate-300">
                <FileCode className="w-4 h-4 text-emerald-400" />
                <span>ad_proxy/config.yaml</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => submitConfig(true)}
                  disabled={validating || saving}
                  className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium rounded transition-colors disabled:opacity-50 text-xs whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{validating ? 'Checking...' : 'Validate Syntax Only'}</span>
                </button>
                <button
                  onClick={() => submitConfig(false)}
                  disabled={saving || validating}
                  className="flex items-center gap-1.5 px-3 py-1 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold rounded transition-colors disabled:opacity-50 text-xs whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{saving ? 'Applying...' : 'Validate & Apply'}</span>
                </button>
              </div>
            </div>

            <textarea
              value={yamlContent}
              onChange={(e) => setYamlContent(e.target.value)}
              rows={22}
              className="w-full bg-slate-950 text-slate-100 font-mono text-xs p-4 focus:outline-none resize-y leading-relaxed"
              spellCheck={false}
            />
          </div>

          {checkOutput && (
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/80">
              <div className="text-xs font-semibold text-slate-300 mb-1.5">Configuration Validator Output:</div>
              <pre className="text-[11px] font-mono text-emerald-400 whitespace-pre-wrap">{checkOutput}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
