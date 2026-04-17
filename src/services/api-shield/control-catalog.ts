// ═══════════════════════════════════════════════════════════════════
// API Shield Advisor — Control Catalog
// ═══════════════════════════════════════════════════════════════════
// Complete catalog of 90+ security controls organized by domain,
// derived from the F5 XC API Security guide. Each control maps to
// OWASP API Security Top 10, includes threat scenarios, implementation
// paths, and phased rollout metadata.
// ═══════════════════════════════════════════════════════════════════

import type {
  SecurityControl,
  ControlPhase,
  ControlPriority,
  PhaseProgress,
  OWASPCoverage,
} from './types';

// ─── Domain ID type (local, used for organizing the catalog) ────

export type ControlDomainId =
  | 'discovery'
  | 'schema'
  | 'rate_limiting'
  | 'waf'
  | 'bot_defense'
  | 'ddos'
  | 'access_control'
  | 'sensitive_data'
  | 'threat_detection'
  | 'devops'
  | 'monitoring';

export interface ControlDomainMeta {
  id: ControlDomainId;
  name: string;
  description: string;
  icon: string;
  controlIds: string[];
}

// ─── Helper: build a SecurityControl ────────────────────────────

function ctrl(
  id: string,
  name: string,
  description: string,
  phase: ControlPhase,
  priority: ControlPriority,
  owasp: string[],
): SecurityControl {
  return {
    id,
    name,
    description,
    phase,
    priority,
    status: 'unknown',
    details: '',
    owaspMapping: owasp,
  };
}

// ═════════════════════════════════════════════════════════════════
// Domain 1: API Discovery
// ═════════════════════════════════════════════════════════════════

const discoveryControls: SecurityControl[] = [
  ctrl(
    'discovery_traffic_based',
    'Traffic-Based API Discovery',
    'Enable automatic API discovery from live traffic to build a real-time inventory of all API endpoints, methods, and parameters.',
    'foundation',
    'critical',
    ['API9'],
  ),
  ctrl(
    'discovery_sensitive_data',
    'Sensitive Data Detection in Discovery',
    'Enable PII and sensitive data detection within API Discovery to identify endpoints transmitting credit cards, SSNs, tokens, etc.',
    'foundation',
    'critical',
    ['API3', 'API8'],
  ),
  ctrl(
    'discovery_shadow_api_detection',
    'Shadow API Detection',
    'Monitor for undocumented API endpoints discovered in traffic that do not match uploaded OpenAPI specifications.',
    'visibility',
    'high',
    ['API9'],
  ),
  ctrl(
    'discovery_authentication_state',
    'Authentication State Tracking',
    'Track authentication status of discovered API endpoints to identify unauthenticated APIs handling sensitive operations.',
    'visibility',
    'high',
    ['API2'],
  ),
  ctrl(
    'discovery_api_groups',
    'API Group Classification',
    'Organize discovered APIs into logical groups for differential policy application and monitoring.',
    'enforcement',
    'medium',
    ['API9'],
  ),
  ctrl(
    'discovery_inventory_review',
    'Periodic Inventory Review',
    'Establish a regular review cadence for the API inventory to detect changes, new shadow APIs, and deprecated endpoints.',
    'advanced',
    'medium',
    ['API9'],
  ),
  ctrl(
    'discovery_learnt_schema',
    'Learnt Schema Generation',
    'Use API Discovery to auto-generate OpenAPI schemas from observed traffic for endpoints without uploaded specs.',
    'visibility',
    'high',
    ['API8', 'API3'],
  ),
  ctrl(
    'discovery_zombie_api_detection',
    'Zombie API Detection',
    'Identify deprecated or outdated API versions still receiving traffic that should be decommissioned.',
    'enforcement',
    'high',
    ['API9'],
  ),
  ctrl(
    'discovery_endpoint_risk_scoring',
    'Endpoint Risk Scoring',
    'Assign risk scores to discovered endpoints based on authentication state, PII exposure, and attack surface.',
    'visibility',
    'medium',
    ['API9', 'API3'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 2: Schema Validation
// ═════════════════════════════════════════════════════════════════

const schemaControls: SecurityControl[] = [
  ctrl(
    'schema_oas_upload',
    'OpenAPI Spec Upload',
    'Upload OpenAPI (Swagger) specification files to define expected API structure, parameters, and response types.',
    'foundation',
    'critical',
    ['API8', 'API3'],
  ),
  ctrl(
    'schema_request_validation',
    'Request Schema Validation',
    'Enable validation of incoming requests against the OpenAPI spec to block malformed or unexpected payloads.',
    'visibility',
    'critical',
    ['API3', 'API8'],
  ),
  ctrl(
    'schema_response_validation',
    'Response Schema Validation',
    'Validate API responses against the spec to detect data leakage and unexpected response structures.',
    'enforcement',
    'high',
    ['API3'],
  ),
  ctrl(
    'schema_validation_mode_report',
    'Schema Validation in Report Mode',
    'Start with report mode to observe violations without blocking, identifying false positives before enforcement.',
    'visibility',
    'high',
    ['API8'],
  ),
  ctrl(
    'schema_validation_mode_block',
    'Schema Validation in Block Mode',
    'Switch to blocking mode after tuning to actively reject non-conforming requests.',
    'enforcement',
    'high',
    ['API8', 'API3'],
  ),
  ctrl(
    'schema_custom_rules',
    'Custom Validation Rules',
    'Define custom validation rules for business-specific constraints beyond what the OpenAPI spec covers (e.g., field length limits, regex patterns).',
    'advanced',
    'medium',
    ['API8'],
  ),
  ctrl(
    'schema_api_definition_attach',
    'API Definition Attached to LB',
    'Ensure the uploaded OpenAPI specification is attached to the HTTP Load Balancer for enforcement.',
    'foundation',
    'critical',
    ['API8'],
  ),
  ctrl(
    'schema_version_management',
    'API Spec Version Management',
    'Maintain versioned OpenAPI specs and update them as the API evolves to prevent schema drift.',
    'advanced',
    'medium',
    ['API8', 'API9'],
  ),
  ctrl(
    'schema_parameter_validation',
    'Query/Header Parameter Validation',
    'Validate query parameters and headers against the spec to prevent injection via overlooked input vectors.',
    'enforcement',
    'high',
    ['API8', 'API3'],
  ),
  ctrl(
    'schema_content_type_enforcement',
    'Content-Type Enforcement',
    'Enforce expected Content-Type headers and reject requests with unexpected media types to prevent deserialization attacks.',
    'visibility',
    'medium',
    ['API8'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 3: Rate Limiting
// ═════════════════════════════════════════════════════════════════

const rateLimitingControls: SecurityControl[] = [
  ctrl(
    'rate_limit_global',
    'Global Rate Limiting',
    'Configure global rate limits on the HTTP Load Balancer to cap total request volume and prevent volumetric abuse.',
    'visibility',
    'high',
    ['API4'],
  ),
  ctrl(
    'rate_limit_per_client',
    'Per-Client Rate Limiting',
    'Apply rate limits per client (by IP, API key, or user identity) to prevent individual actors from monopolizing API resources.',
    'visibility',
    'high',
    ['API4'],
  ),
  ctrl(
    'rate_limit_per_endpoint',
    'Per-Endpoint Rate Limiting',
    'Set different rate limits for specific API endpoints based on their expected traffic patterns and sensitivity.',
    'enforcement',
    'high',
    ['API4'],
  ),
  ctrl(
    'rate_limit_custom_identifier',
    'Custom Rate Limit Identifier',
    'Use custom identifiers (API keys, JWT claims, headers) for rate limiting instead of just IP to handle shared IPs and proxies.',
    'enforcement',
    'medium',
    ['API4'],
  ),
  ctrl(
    'rate_limit_response_headers',
    'Rate Limit Response Headers',
    'Return rate limit headers (X-RateLimit-*) in responses so API consumers can implement client-side throttling.',
    'advanced',
    'low',
    ['API4'],
  ),
  ctrl(
    'rate_limit_service_policy',
    'Rate Limiting via Service Policy',
    'Use service policies for advanced rate limiting rules with conditional logic based on request attributes.',
    'advanced',
    'medium',
    ['API4'],
  ),
  ctrl(
    'rate_limit_burst_control',
    'Burst Rate Control',
    'Configure burst limits to handle legitimate traffic spikes while still capping sustained abusive request rates.',
    'enforcement',
    'medium',
    ['API4'],
  ),
  ctrl(
    'rate_limit_write_endpoints',
    'Write Endpoint Rate Limits',
    'Apply stricter rate limits to write operations (POST, PUT, DELETE) to prevent data modification abuse.',
    'enforcement',
    'high',
    ['API4', 'API6'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 4: WAF Protection
// ═════════════════════════════════════════════════════════════════

const wafControls: SecurityControl[] = [
  ctrl(
    'waf_app_firewall',
    'WAF Policy Assigned',
    'Assign a Web Application Firewall policy to the HTTP Load Balancer with standard attack signature detection.',
    'foundation',
    'critical',
    ['API8'],
  ),
  ctrl(
    'waf_blocking_mode',
    'WAF in Blocking Mode',
    'Set the WAF to blocking mode to actively reject malicious requests rather than just logging them.',
    'visibility',
    'critical',
    ['API8'],
  ),
  ctrl(
    'waf_high_medium_signatures',
    'High & Medium Accuracy Signatures',
    'Enable high and medium accuracy attack signatures for broad coverage with acceptable false positive rates.',
    'foundation',
    'critical',
    ['API8'],
  ),
  ctrl(
    'waf_exclusion_rules',
    'WAF Exclusion Rules',
    'Configure exclusion rules for known false positives to prevent blocking legitimate API traffic.',
    'visibility',
    'high',
    ['API8'],
  ),
  ctrl(
    'waf_attack_types_all',
    'All Attack Types Active',
    'Ensure all WAF attack type categories are active including SQLi, XSS, command injection, and protocol violations.',
    'foundation',
    'high',
    ['API8'],
  ),
  ctrl(
    'waf_api_specific_signatures',
    'API-Specific WAF Signatures',
    'Enable WAF signatures specifically designed for API attacks including JSON/XML injection and API protocol violations.',
    'visibility',
    'high',
    ['API8'],
  ),
  ctrl(
    'waf_bot_signature_detection',
    'Bot Signature Detection via WAF',
    'Enable bot detection signatures within the WAF to catch known malicious bot patterns and user agents.',
    'visibility',
    'medium',
    ['API8'],
  ),
  ctrl(
    'waf_csrf_protection',
    'CSRF Protection',
    'Enable Cross-Site Request Forgery protection in the WAF for state-changing API operations.',
    'enforcement',
    'medium',
    ['API8'],
  ),
  ctrl(
    'waf_graphql_protection',
    'GraphQL Protection',
    'Enable GraphQL-specific WAF protections including query depth limiting, introspection control, and batch query restrictions.',
    'enforcement',
    'medium',
    ['API8', 'API4'],
  ),
  ctrl(
    'waf_allowed_methods',
    'HTTP Method Restriction',
    'Restrict allowed HTTP methods per endpoint to prevent unexpected operations (e.g., block DELETE on read-only resources).',
    'visibility',
    'medium',
    ['API5', 'API8'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 5: Bot Defense
// ═════════════════════════════════════════════════════════════════

const botDefenseControls: SecurityControl[] = [
  ctrl(
    'bot_defense_enable',
    'Bot Defense Enabled',
    'Enable Bot Defense on the HTTP Load Balancer to detect and mitigate automated threats.',
    'visibility',
    'high',
    ['API2', 'API4'],
  ),
  ctrl(
    'bot_defense_js_challenge',
    'JavaScript Challenge',
    'Configure JavaScript challenges for suspicious clients to verify browser capability and filter headless bots.',
    'visibility',
    'high',
    ['API2'],
  ),
  ctrl(
    'bot_defense_captcha',
    'CAPTCHA Challenge',
    'Enable CAPTCHA challenges for high-risk operations like login, registration, and password reset.',
    'enforcement',
    'medium',
    ['API2', 'API4'],
  ),
  ctrl(
    'bot_defense_mobile_sdk',
    'Mobile SDK Integration',
    'Integrate F5 Mobile SDK for mobile app bot defense, providing device attestation and behavioral analysis.',
    'advanced',
    'medium',
    ['API2'],
  ),
  ctrl(
    'bot_defense_api_endpoints',
    'Bot Defense on API Endpoints',
    'Apply bot defense policies specifically to API endpoints with custom rules for programmatic access patterns.',
    'enforcement',
    'high',
    ['API2', 'API4'],
  ),
  ctrl(
    'bot_defense_good_bot_allowlist',
    'Good Bot Allowlist',
    'Configure an allowlist for verified good bots (search engines, monitoring) to prevent false positives on legitimate crawlers.',
    'visibility',
    'medium',
    ['API2'],
  ),
  ctrl(
    'bot_defense_behavioral_analysis',
    'Behavioral Bot Analysis',
    'Enable behavioral analysis to detect advanced bots that mimic human browsing patterns and evade signature-based detection.',
    'advanced',
    'high',
    ['API2', 'API6'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 6: DDoS Protection
// ═════════════════════════════════════════════════════════════════

const ddosControls: SecurityControl[] = [
  ctrl(
    'ddos_l7_protection',
    'L7 DDoS Protection',
    'Enable Layer 7 DDoS protection on the HTTP Load Balancer with appropriate RPS thresholds.',
    'foundation',
    'high',
    ['API4'],
  ),
  ctrl(
    'ddos_auto_mitigation',
    'Auto-Mitigation Enabled',
    'Enable automatic DDoS mitigation actions (block, JS challenge, or CAPTCHA) when thresholds are exceeded.',
    'visibility',
    'high',
    ['API4'],
  ),
  ctrl(
    'ddos_slow_request',
    'Slow DDoS Protection',
    'Configure request and header timeout settings to mitigate slow HTTP attacks (Slowloris, slow POST).',
    'visibility',
    'medium',
    ['API4'],
  ),
  ctrl(
    'ddos_custom_rps_threshold',
    'Custom RPS Threshold',
    'Set a data-driven RPS threshold based on actual traffic patterns instead of relying on the default (10,000 RPS).',
    'enforcement',
    'medium',
    ['API4'],
  ),
  ctrl(
    'ddos_mitigation_rules',
    'DDoS Mitigation Rules',
    'Define custom DDoS mitigation rules based on source IP, ASN, country, or other request attributes.',
    'advanced',
    'medium',
    ['API4'],
  ),
  ctrl(
    'ddos_js_challenge_delay',
    'JavaScript Challenge Delay Tuning',
    'Tune JS challenge delay and cookie expiry for optimal balance between security and user experience.',
    'advanced',
    'low',
    ['API4'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 7: Access Control
// ═════════════════════════════════════════════════════════════════

const accessControlControls: SecurityControl[] = [
  ctrl(
    'access_service_policy',
    'Service Policy Assigned',
    'Assign a service policy to the HTTP Load Balancer to enforce access control rules.',
    'foundation',
    'critical',
    ['API1', 'API5'],
  ),
  ctrl(
    'access_geo_filtering',
    'Geo-Based Access Filtering',
    'Restrict API access by geographic location, blocking or challenging requests from unexpected regions.',
    'visibility',
    'medium',
    ['API5'],
  ),
  ctrl(
    'access_ip_allowlist',
    'IP Allow/Deny Lists',
    'Configure IP prefix lists to allow or deny access from specific IP ranges for trusted/blocked sources.',
    'visibility',
    'high',
    ['API5'],
  ),
  ctrl(
    'access_mtls',
    'Mutual TLS (mTLS)',
    'Enable mutual TLS authentication requiring client certificates for service-to-service API communication.',
    'enforcement',
    'high',
    ['API2'],
  ),
  ctrl(
    'access_cors_policy',
    'CORS Policy Configuration',
    'Configure Cross-Origin Resource Sharing policies to restrict which origins can call the API from browsers.',
    'visibility',
    'medium',
    ['API5', 'API8'],
  ),
  ctrl(
    'access_jwt_validation',
    'JWT Token Validation',
    'Enable JWT validation in service policies to verify token signatures, claims, and expiration.',
    'enforcement',
    'high',
    ['API2', 'API1'],
  ),
  ctrl(
    'access_api_key_policy',
    'API Key Enforcement',
    'Enforce API key requirements via service policies for machine-to-machine API access.',
    'enforcement',
    'medium',
    ['API2'],
  ),
  ctrl(
    'access_per_route_policies',
    'Per-Route Access Policies',
    'Apply different access control policies per API route to implement least-privilege access.',
    'advanced',
    'medium',
    ['API1', 'API5'],
  ),
  ctrl(
    'access_oauth2_integration',
    'OAuth2/OIDC Integration',
    'Integrate OAuth2 or OpenID Connect for delegated authorization, enabling fine-grained token-based access control.',
    'enforcement',
    'high',
    ['API1', 'API2'],
  ),
  ctrl(
    'access_header_manipulation',
    'Security Header Injection',
    'Add security headers (X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security) to API responses.',
    'visibility',
    'medium',
    ['API8'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 8: Sensitive Data
// ═════════════════════════════════════════════════════════════════

const sensitiveDataControls: SecurityControl[] = [
  ctrl(
    'sensitive_data_guard',
    'Data Guard Enabled',
    'Enable Data Guard on the WAF to detect and mask sensitive data (SSN, credit cards, etc.) in API responses.',
    'visibility',
    'high',
    ['API3'],
  ),
  ctrl(
    'sensitive_data_discovery',
    'Sensitive Data Discovery',
    'Enable sensitive data discovery to automatically identify PII, credentials, and regulated data in API traffic.',
    'visibility',
    'high',
    ['API3'],
  ),
  ctrl(
    'sensitive_data_response_masking',
    'Response Data Masking',
    'Configure response masking rules to automatically redact sensitive fields before they reach API consumers.',
    'enforcement',
    'high',
    ['API3'],
  ),
  ctrl(
    'sensitive_data_custom_patterns',
    'Custom Sensitive Data Patterns',
    'Define custom regex patterns for organization-specific sensitive data types beyond built-in detections.',
    'advanced',
    'medium',
    ['API3'],
  ),
  ctrl(
    'sensitive_data_log_redaction',
    'Log Data Redaction',
    'Ensure sensitive data is redacted from logs and security events to prevent data exposure through monitoring systems.',
    'enforcement',
    'medium',
    ['API3'],
  ),
  ctrl(
    'sensitive_data_pci_compliance',
    'PCI-DSS Data Compliance',
    'Configure Data Guard rules specifically for PCI-DSS compliance, ensuring credit card numbers are detected and masked.',
    'enforcement',
    'high',
    ['API3'],
  ),
  ctrl(
    'sensitive_data_error_sanitization',
    'Error Response Sanitization',
    'Sanitize error responses to remove stack traces, internal IPs, database errors, and debug information.',
    'visibility',
    'high',
    ['API3', 'API8'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 9: Threat Detection
// ═════════════════════════════════════════════════════════════════

const threatDetectionControls: SecurityControl[] = [
  ctrl(
    'threat_malicious_user',
    'Malicious User Detection',
    'Enable malicious user detection to identify and track threat actors across sessions based on behavioral analysis.',
    'visibility',
    'high',
    ['API2', 'API4'],
  ),
  ctrl(
    'threat_ip_reputation',
    'IP Reputation Filtering',
    'Enable IP reputation service to block or challenge requests from known malicious IP addresses.',
    'foundation',
    'high',
    ['API8'],
  ),
  ctrl(
    'threat_mesh',
    'Threat Mesh Intelligence',
    'Enable Threat Mesh to leverage F5 global threat intelligence for cross-customer threat correlation.',
    'visibility',
    'high',
    ['API8'],
  ),
  ctrl(
    'threat_user_identification',
    'User Identification',
    'Configure user identification to track API users by header, cookie, or JWT claim for behavioral analysis.',
    'visibility',
    'high',
    ['API2', 'API4'],
  ),
  ctrl(
    'threat_ip_categories',
    'IP Threat Categories',
    'Configure which IP threat categories to enforce: spam sources, botnets, scanners, proxies, tor nodes.',
    'enforcement',
    'medium',
    ['API8'],
  ),
  ctrl(
    'threat_failed_auth_tracking',
    'Failed Authentication Tracking',
    'Monitor and alert on excessive failed authentication attempts per user/IP to detect brute force attacks.',
    'enforcement',
    'high',
    ['API2'],
  ),
  ctrl(
    'threat_api_abuse_detection',
    'API Abuse Pattern Detection',
    'Detect API abuse patterns such as enumeration, scraping, and data harvesting through behavioral analysis.',
    'advanced',
    'high',
    ['API4', 'API6'],
  ),
  ctrl(
    'threat_geo_anomaly_detection',
    'Geographic Anomaly Detection',
    'Detect and alert on API access from unusual geographic locations based on user behavioral baselines.',
    'advanced',
    'medium',
    ['API2', 'API8'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 10: DevOps Integration
// ═════════════════════════════════════════════════════════════════

const devopsControls: SecurityControl[] = [
  ctrl(
    'devops_terraform',
    'Terraform Provider Integration',
    'Use the F5 XC Terraform provider to define API security configurations as code for repeatable deployments.',
    'advanced',
    'medium',
    ['API8', 'API9'],
  ),
  ctrl(
    'devops_ci_cd_spec_upload',
    'CI/CD OpenAPI Spec Upload',
    'Integrate OpenAPI spec upload into CI/CD pipelines to automatically update API definitions on deployment.',
    'advanced',
    'medium',
    ['API8', 'API9'],
  ),
  ctrl(
    'devops_gitops',
    'GitOps Configuration Management',
    'Store all API security configurations in Git and use GitOps workflows for change management and audit trails.',
    'advanced',
    'medium',
    ['API9'],
  ),
  ctrl(
    'devops_api_security_testing',
    'API Security Testing in Pipeline',
    'Integrate API security testing tools (DAST, SAST) into CI/CD pipelines to detect vulnerabilities before deployment.',
    'advanced',
    'medium',
    ['API8', 'API9'],
  ),
  ctrl(
    'devops_policy_as_code',
    'Policy-as-Code',
    'Define service policies, WAF exclusions, and rate limits as code artifacts managed alongside application code.',
    'advanced',
    'low',
    ['API8'],
  ),
  ctrl(
    'devops_environment_promotion',
    'Environment Promotion Workflow',
    'Establish promotion workflows (dev > staging > prod) for API security configurations with validation gates.',
    'advanced',
    'low',
    ['API9'],
  ),
  ctrl(
    'devops_vesctl_automation',
    'vesctl CLI Automation',
    'Use vesctl CLI for scripted configuration management, batch updates, and automated policy deployment.',
    'advanced',
    'medium',
    ['API8', 'API9'],
  ),
  ctrl(
    'devops_config_drift_detection',
    'Configuration Drift Detection',
    'Monitor for configuration drift between declared state and actual deployed configurations across environments.',
    'advanced',
    'medium',
    ['API8', 'API9'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// Domain 11: Monitoring & Alerting
// ═════════════════════════════════════════════════════════════════

const monitoringControls: SecurityControl[] = [
  ctrl(
    'monitor_security_dashboard',
    'Security Dashboard Review',
    'Regularly review the F5 XC security dashboard for API threat trends, top attacks, and anomalous patterns.',
    'foundation',
    'high',
    ['API9'],
  ),
  ctrl(
    'monitor_log_streaming',
    'Log Streaming to SIEM',
    'Configure global log receivers to stream security events to external SIEM systems for centralized analysis.',
    'enforcement',
    'medium',
    ['API9'],
  ),
  ctrl(
    'monitor_alert_policies',
    'Alert Policy Configuration',
    'Create alert policies for critical security events: WAF blocks, DDoS triggers, rate limit hits, and bot detections.',
    'visibility',
    'high',
    ['API9'],
  ),
  ctrl(
    'monitor_alert_receivers',
    'Alert Receivers (Slack, Email, Webhook)',
    'Configure alert receivers to deliver security notifications to the appropriate teams via Slack, email, PagerDuty, or webhooks.',
    'visibility',
    'high',
    ['API9'],
  ),
  ctrl(
    'monitor_security_event_logging',
    'Security Event Logging',
    'Ensure full security event logging is enabled on all HTTP Load Balancers, not just access logs.',
    'foundation',
    'high',
    ['API9'],
  ),
  ctrl(
    'monitor_api_traffic_anomalies',
    'API Traffic Anomaly Detection',
    'Monitor for anomalous API traffic patterns: sudden spikes, unusual methods, new endpoints, or geographic anomalies.',
    'advanced',
    'medium',
    ['API9', 'API4'],
  ),
  ctrl(
    'monitor_compliance_reporting',
    'Compliance Reporting',
    'Generate periodic compliance reports mapping API security controls to regulatory requirements (PCI-DSS, GDPR, SOC2).',
    'advanced',
    'low',
    ['API9'],
  ),
  ctrl(
    'monitor_incident_response_plan',
    'API Incident Response Plan',
    'Document and test an API security incident response plan including escalation paths and communication procedures.',
    'advanced',
    'medium',
    ['API9'],
  ),
  ctrl(
    'monitor_custom_dashboards',
    'Custom API Security Dashboards',
    'Build custom dashboards focused on API-specific metrics: endpoint latency, error rates, auth failures, and schema violations.',
    'advanced',
    'low',
    ['API9'],
  ),
  ctrl(
    'monitor_sla_tracking',
    'API SLA Monitoring',
    'Track API availability, latency, and error rate SLAs with automated alerting on SLA breaches.',
    'advanced',
    'medium',
    ['API9', 'API4'],
  ),
];

// ═════════════════════════════════════════════════════════════════
// All controls flat list
// ═════════════════════════════════════════════════════════════════

const ALL_CONTROLS: SecurityControl[] = [
  ...discoveryControls,
  ...schemaControls,
  ...rateLimitingControls,
  ...wafControls,
  ...botDefenseControls,
  ...ddosControls,
  ...accessControlControls,
  ...sensitiveDataControls,
  ...threatDetectionControls,
  ...devopsControls,
  ...monitoringControls,
];

// ═════════════════════════════════════════════════════════════════
// Domain Metadata (exported for UI)
// ═════════════════════════════════════════════════════════════════

/** Domain metadata with associated control IDs for organization */
export const CONTROL_DOMAINS: ControlDomainMeta[] = [
  {
    id: 'discovery',
    name: 'API Discovery',
    description: 'Automatic API endpoint discovery, shadow API detection, and inventory management',
    icon: 'Radar',
    controlIds: discoveryControls.map((c) => c.id),
  },
  {
    id: 'schema',
    name: 'Schema Validation',
    description: 'OpenAPI spec upload, schema enforcement, and request/response validation',
    icon: 'FileCheck',
    controlIds: schemaControls.map((c) => c.id),
  },
  {
    id: 'rate_limiting',
    name: 'Rate Limiting',
    description: 'API rate limits, per-client throttling, and abuse prevention',
    icon: 'Gauge',
    controlIds: rateLimitingControls.map((c) => c.id),
  },
  {
    id: 'waf',
    name: 'WAF Protection',
    description: 'Web Application Firewall rules, attack signatures, and injection protection',
    icon: 'Shield',
    controlIds: wafControls.map((c) => c.id),
  },
  {
    id: 'bot_defense',
    name: 'Bot Defense',
    description: 'Bot detection, JavaScript challenges, and automated threat mitigation',
    icon: 'Bot',
    controlIds: botDefenseControls.map((c) => c.id),
  },
  {
    id: 'ddos',
    name: 'DDoS Protection',
    description: 'L7 DDoS protection, auto-mitigation, slow DDoS, and volumetric attack defense',
    icon: 'Zap',
    controlIds: ddosControls.map((c) => c.id),
  },
  {
    id: 'access_control',
    name: 'Access Control',
    description: 'Authentication, authorization, mTLS, CORS, and service policies',
    icon: 'Lock',
    controlIds: accessControlControls.map((c) => c.id),
  },
  {
    id: 'sensitive_data',
    name: 'Sensitive Data',
    description: 'Data Guard, PII discovery, response masking, and data loss prevention',
    icon: 'Eye',
    controlIds: sensitiveDataControls.map((c) => c.id),
  },
  {
    id: 'threat_detection',
    name: 'Threat Detection',
    description: 'Malicious user detection, IP reputation, Threat Mesh, and user tracking',
    icon: 'AlertTriangle',
    controlIds: threatDetectionControls.map((c) => c.id),
  },
  {
    id: 'devops',
    name: 'DevOps Integration',
    description: 'CI/CD integration, Terraform, GitOps, and automated security deployment',
    icon: 'GitBranch',
    controlIds: devopsControls.map((c) => c.id),
  },
  {
    id: 'monitoring',
    name: 'Monitoring & Alerting',
    description: 'Log streaming, SIEM integration, alerts, and security dashboards',
    icon: 'Activity',
    controlIds: monitoringControls.map((c) => c.id),
  },
];

// ═════════════════════════════════════════════════════════════════
// OWASP API Security Top 10 (2023)
// ═════════════════════════════════════════════════════════════════

/**
 * OWASP API Security Top 10 (2023) definitions.
 * Each item lists the control IDs from the catalog that address the risk.
 */
export const OWASP_API_TOP_10: Array<{
  id: string;
  name: string;
  description: string;
  controls: string[];
}> = [
  {
    id: 'API1',
    name: 'Broken Object Level Authorization',
    description: 'APIs expose endpoints that handle object identifiers, creating a wide attack surface for object-level access control issues.',
    controls: [
      'access_service_policy', 'access_per_route_policies', 'access_jwt_validation',
      'schema_request_validation', 'threat_malicious_user',
    ],
  },
  {
    id: 'API2',
    name: 'Broken Authentication',
    description: 'Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit flaws.',
    controls: [
      'access_mtls', 'access_jwt_validation', 'access_api_key_policy',
      'bot_defense_enable', 'bot_defense_js_challenge', 'bot_defense_captcha',
      'threat_malicious_user', 'threat_user_identification', 'threat_failed_auth_tracking',
      'discovery_authentication_state',
    ],
  },
  {
    id: 'API3',
    name: 'Broken Object Property Level Authorization',
    description: 'APIs expose endpoints that return all object properties without considering which should be accessible, leading to excessive data exposure.',
    controls: [
      'schema_oas_upload', 'schema_request_validation', 'schema_response_validation',
      'sensitive_data_guard', 'sensitive_data_discovery', 'sensitive_data_response_masking',
      'discovery_sensitive_data', 'discovery_learnt_schema',
    ],
  },
  {
    id: 'API4',
    name: 'Unrestricted Resource Consumption',
    description: 'APIs do not restrict the number or size of resources that can be requested, leading to DoS and financial damage.',
    controls: [
      'rate_limit_global', 'rate_limit_per_client', 'rate_limit_per_endpoint',
      'rate_limit_custom_identifier', 'rate_limit_service_policy',
      'ddos_l7_protection', 'ddos_auto_mitigation', 'ddos_slow_request', 'ddos_custom_rps_threshold',
      'bot_defense_enable', 'bot_defense_api_endpoints',
      'threat_malicious_user', 'threat_user_identification',
      'monitor_api_traffic_anomalies',
    ],
  },
  {
    id: 'API5',
    name: 'Broken Function Level Authorization',
    description: 'Complex access control policies with different hierarchies, groups, and roles create authorization flaws.',
    controls: [
      'access_service_policy', 'access_per_route_policies', 'access_geo_filtering',
      'access_ip_allowlist', 'access_cors_policy',
    ],
  },
  {
    id: 'API6',
    name: 'Unrestricted Access to Sensitive Business Flows',
    description: 'APIs expose business flows that can be exploited by automated attacks when consumed excessively.',
    controls: [
      'bot_defense_enable', 'bot_defense_js_challenge', 'bot_defense_captcha',
      'bot_defense_api_endpoints',
      'rate_limit_per_endpoint', 'rate_limit_per_client',
    ],
  },
  {
    id: 'API7',
    name: 'Server Side Request Forgery',
    description: 'SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URI.',
    controls: [
      'waf_app_firewall', 'waf_blocking_mode', 'waf_api_specific_signatures',
      'schema_request_validation',
    ],
  },
  {
    id: 'API8',
    name: 'Security Misconfiguration',
    description: 'APIs and supporting systems typically contain complex configurations that can be overlooked, creating security weaknesses.',
    controls: [
      'waf_app_firewall', 'waf_blocking_mode', 'waf_high_medium_signatures', 'waf_attack_types_all',
      'waf_api_specific_signatures', 'waf_exclusion_rules', 'waf_bot_signature_detection', 'waf_csrf_protection',
      'schema_oas_upload', 'schema_request_validation', 'schema_custom_rules',
      'access_cors_policy',
      'threat_ip_reputation', 'threat_mesh', 'threat_ip_categories',
      'devops_terraform', 'devops_ci_cd_spec_upload', 'devops_policy_as_code',
      'discovery_sensitive_data',
      'schema_version_management',
    ],
  },
  {
    id: 'API9',
    name: 'Improper Inventory Management',
    description: 'APIs tend to expose more endpoints than traditional web apps, making proper documentation and inventory critical.',
    controls: [
      'discovery_traffic_based', 'discovery_shadow_api_detection', 'discovery_api_groups',
      'discovery_inventory_review',
      'schema_oas_upload', 'schema_version_management',
      'monitor_security_dashboard', 'monitor_log_streaming', 'monitor_alert_policies',
      'monitor_alert_receivers', 'monitor_security_event_logging',
      'monitor_api_traffic_anomalies', 'monitor_compliance_reporting',
      'monitor_incident_response_plan',
      'devops_gitops', 'devops_ci_cd_spec_upload', 'devops_api_security_testing',
      'devops_environment_promotion',
    ],
  },
  {
    id: 'API10',
    name: 'Unsafe Consumption of APIs',
    description: 'Developers tend to trust data from third-party APIs more than user input, adopting weaker security standards.',
    controls: [
      'schema_request_validation', 'schema_response_validation',
      'waf_app_firewall', 'waf_api_specific_signatures',
      'access_mtls',
    ],
  },
];

// ═════════════════════════════════════════════════════════════════
// Implementation Phases
// ═════════════════════════════════════════════════════════════════

const PHASE_NAMES: Record<ControlPhase, string> = {
  foundation: 'Foundation',
  visibility: 'Visibility & Detection',
  enforcement: 'Enforcement & Blocking',
  advanced: 'Advanced & Optimization',
};

const PHASE_ORDER: ControlPhase[] = ['foundation', 'visibility', 'enforcement', 'advanced'];

function countByPhase(phase: ControlPhase): number {
  return ALL_CONTROLS.filter((c) => c.phase === phase).length;
}

/**
 * Implementation phases with control counts.
 * enabledControls, partialControls, disabledControls, and completionPercent
 * are initialized to 0 (populated during assessment).
 */
export const IMPLEMENTATION_PHASES: PhaseProgress[] = [
  {
    phase: 'foundation',
    phaseName: 'Foundation',
    totalControls: countByPhase('foundation'),
    enabledControls: 0,
    partialControls: 0,
    disabledControls: 0,
    completionPercent: 0,
  },
  {
    phase: 'visibility',
    phaseName: 'Visibility & Detection',
    totalControls: countByPhase('visibility'),
    enabledControls: 0,
    partialControls: 0,
    disabledControls: 0,
    completionPercent: 0,
  },
  {
    phase: 'enforcement',
    phaseName: 'Enforcement & Blocking',
    totalControls: countByPhase('enforcement'),
    enabledControls: 0,
    partialControls: 0,
    disabledControls: 0,
    completionPercent: 0,
  },
  {
    phase: 'advanced',
    phaseName: 'Advanced & Optimization',
    totalControls: countByPhase('advanced'),
    enabledControls: 0,
    partialControls: 0,
    disabledControls: 0,
    completionPercent: 0,
  },
];

// ═════════════════════════════════════════════════════════════════
// Lookup Indexes
// ═════════════════════════════════════════════════════════════════

/** Map of control ID to control for fast lookup */
const controlIndex = new Map<string, SecurityControl>(
  ALL_CONTROLS.map((c) => [c.id, c]),
);

/** Map of domain ID to control IDs */
const domainControlMap = new Map<ControlDomainId, string[]>(
  CONTROL_DOMAINS.map((d) => [d.id, d.controlIds]),
);

/** Map of phase to controls */
const phaseControlMap = new Map<ControlPhase, SecurityControl[]>();
for (const c of ALL_CONTROLS) {
  const existing = phaseControlMap.get(c.phase) || [];
  existing.push(c);
  phaseControlMap.set(c.phase, existing);
}

// ═════════════════════════════════════════════════════════════════
// Public API
// ═════════════════════════════════════════════════════════════════

/**
 * Look up a security control by its unique ID.
 * Returns undefined if the ID is not found.
 */
export function getControlById(id: string): SecurityControl | undefined {
  return controlIndex.get(id);
}

/**
 * Get all controls belonging to a specific domain.
 * Returns fresh copies to prevent mutation of the catalog.
 */
export function getControlsByDomain(domain: ControlDomainId): SecurityControl[] {
  const ids = domainControlMap.get(domain);
  if (!ids) return [];
  return ids
    .map((id) => controlIndex.get(id))
    .filter((c): c is SecurityControl => c !== undefined)
    .map((c) => ({ ...c }));
}

/**
 * Get all controls belonging to a specific implementation phase.
 * Returns fresh copies to prevent mutation of the catalog.
 */
export function getControlsByPhase(phase: ControlPhase): SecurityControl[] {
  return (phaseControlMap.get(phase) || []).map((c) => ({ ...c }));
}

/**
 * Get a flat array of all controls from the catalog.
 * Returns fresh copies to prevent mutation of the catalog.
 */
export function getAllControls(): SecurityControl[] {
  return ALL_CONTROLS.map((c) => ({ ...c }));
}

/**
 * Get total count of all controls across all domains.
 */
export function getTotalControlCount(): number {
  return ALL_CONTROLS.length;
}

/**
 * Get control IDs that map to a specific OWASP API Top 10 item.
 */
export function getControlsForOWASP(owaspId: string): string[] {
  const item = OWASP_API_TOP_10.find((o) => o.id === owaspId);
  return item ? [...item.controls] : [];
}

/**
 * Build OWASP coverage from a list of controls with assessed statuses.
 */
export function buildOWASPCoverage(controls: SecurityControl[]): OWASPCoverage[] {
  const statusMap = new Map<string, SecurityControl>(
    controls.map((c) => [c.id, c]),
  );

  return OWASP_API_TOP_10.map((item) => {
    const coveredIds = item.controls.filter((id) => {
      const c = statusMap.get(id);
      return c && (c.status === 'enabled' || c.status === 'partial');
    });

    const coveragePercent =
      item.controls.length > 0
        ? Math.round((coveredIds.length / item.controls.length) * 100)
        : 0;

    return {
      id: item.id,
      name: item.name,
      description: item.description,
      coveredByControls: coveredIds,
      coveragePercent,
    };
  });
}

/**
 * Build phase progress from a list of controls with assessed statuses.
 */
export function buildPhaseProgress(controls: SecurityControl[]): PhaseProgress[] {
  return PHASE_ORDER.map((phase) => {
    const phaseControls = controls.filter((c) => c.phase === phase);
    const enabled = phaseControls.filter((c) => c.status === 'enabled').length;
    const partial = phaseControls.filter((c) => c.status === 'partial').length;
    const disabled = phaseControls.filter(
      (c) => c.status === 'disabled' || c.status === 'unknown',
    ).length;
    const total = phaseControls.length;
    const completionPercent =
      total > 0 ? Math.round(((enabled + partial * 0.5) / total) * 100) : 0;

    return {
      phase,
      phaseName: PHASE_NAMES[phase],
      totalControls: total,
      enabledControls: enabled,
      partialControls: partial,
      disabledControls: disabled,
      completionPercent,
    };
  });
}

/**
 * Get the ordered list of implementation phases.
 */
export function getPhaseOrder(): ControlPhase[] {
  return [...PHASE_ORDER];
}

/**
 * Get the domain that a control belongs to, based on its ID prefix.
 */
export function getDomainForControl(controlId: string): ControlDomainId | undefined {
  for (const domain of CONTROL_DOMAINS) {
    if (domain.controlIds.includes(controlId)) {
      return domain.id;
    }
  }
  return undefined;
}
