/**
 * Shared TypeScript interfaces for the Active Directory Secure LDAPS Proxy Console.
 */

export interface CommandMeta {
  name: string;
  description: string;
  category: 'read' | 'write' | 'admin' | 'system';
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  required_params: string[];
  optional_params: string[];
}

export interface ProxyExecutionResult {
  success: boolean;
  status_code: string;
  message: string;
  data?: any;
  request_id?: string;
  duration_ms?: number;
  siem_event?: SiemEvent;
}

export interface SiemEvent {
  event_id: string;
  timestamp: string;
  caller_account: string;
  client_ip: string;
  command: string;
  target_dn?: string;
  filter_string?: string;
  outcome:
    | 'SUCCESS'
    | 'AUTH_FAILED'
    | 'FORBIDDEN_CALLER'
    | 'FORBIDDEN_COMMAND'
    | 'RESTRICTED_TARGET'
    | 'VALIDATION_ERROR'
    | 'UPSTREAM_ERROR'
    | 'SECURITY_ALERT_ROGUE_AGENT'
    | string;
  status_code: string;
  message: string;
  duration_ms: number;
  severity?: number;
  is_high_severity_alert?: boolean;
  alert_rule?: string;
  threat?: {
    indicator: string;
    rule?: string;
    severity?: string;
    risk_score?: number;
    action?: string;
  };
  parameters: Record<string, any>;
  details: Record<string, any>;
  domain: string;
  raw?: string;
}

export interface ServiceAccountRule {
  command: string;
  allowed_groups?: string[];
  restricted_groups?: string[];
  allowed_ous?: string[];
  allowed_attributes?: string[];
  max_search_results?: number;
  require_approval_ticket?: boolean;
}

export interface ServiceAccountPolicy {
  account_identifier: string;
  description: string;
  permitted_commands: string[];
  denied_commands?: string[];
  rules?: ServiceAccountRule[];
}

export interface ParsedProxyConfig {
  domain: {
    domain_name: string;
    base_dn: string;
    domain_controllers: string[];
    ldaps_port: number;
    verify_ssl: boolean;
  };
  upstream_auth: {
    mode: string;
    username?: string;
    gmsa_name?: string;
    secret_provider: string;
  };
  siem: {
    enabled: boolean;
    format: string;
    destinations: string[];
    log_file_path: string;
  };
  service_accounts: ServiceAccountPolicy[];
}
