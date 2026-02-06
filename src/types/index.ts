export interface Credentials {
  tenant: string;
  apiToken: string;
}

export interface Namespace {
  name: string;
  [key: string]: unknown;
}

export interface LoadBalancer {
  name: string;
  namespace?: string;
  spec?: LoadBalancerSpec;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    disable?: boolean;
  };
  system_metadata?: {
    creation_timestamp: string;
  };
}

export interface LoadBalancerSpec {
  domains?: string[];
  routes?: Route[];
  app_firewall?: ObjectRef;
  disable_waf?: boolean;
  https_auto_cert?: TLSConfig;
  https?: TLSConfig;
  advertise_on_public_default_vip?: boolean;
  advertise_on_public?: { public_ip?: ObjectRef } | boolean;
  advertise_custom?: unknown;
  do_not_advertise?: boolean;
  add_hsts_header?: boolean;
  http_redirect?: boolean;
  default_route_pools?: PoolRef[];
  active_service_policies?: { policies: ObjectRef[] };
  user_identification?: ObjectRef;
  user_id_client_ip?: unknown;
  bot_defense?: { policy?: ObjectRef; regional_endpoint?: string };
  disable_bot_defense?: boolean;
  malicious_user_mitigation?: ObjectRef;
  api_definition?: ObjectRef;
  disable_api_definition?: boolean;
  rate_limiter?: ObjectRef;
  rate_limit?: RateLimitConfig;
  enable_api_discovery?: {
    enable_learn_from_redirect_traffic?: boolean;
    discovered_api_settings?: {
      purge_duration_for_inactive_discovered_apis?: number;
    };
  };
  disable_api_discovery?: boolean;
  disable_api_testing?: boolean;
  api_protection_rules?: { api_groups?: unknown[] };
  sensitive_data_disclosure_rules?: unknown;
  default_sensitive_data_policy?: unknown;
  enable_ip_reputation?: boolean | { ip_threat_categories?: string[] };
  ip_reputation?: unknown;
  disable_ip_reputation?: boolean;
  ddos_mitigation_rules?: DDoSMitigationRule[];
  enable_ddos_detection?: boolean;
  ddos_detection?: unknown;
  disable_ddos_detection?: boolean;
  l7_ddos_protection?: L7DDoSProtection;
  slow_ddos_mitigation?: {
    request_headers_timeout?: number;
    request_timeout?: number;
  };
  client_side_defense?: { policy?: ObjectRef };
  disable_client_side_defense?: boolean;
  request_headers_to_add?: Header[];
  response_headers_to_add?: Header[];
  request_headers_to_remove?: string[];
  response_headers_to_remove?: string[];
  cookie_stickiness?: { name?: string };
  enable_automatic_compression?: boolean;
  disable_buffering?: boolean;
  enable_websocket?: boolean;
  idle_timeout?: number;
  max_request_header_size?: number;
  enable_malicious_user_detection?: boolean;
  malicious_user_detection?: unknown;
  disable_malicious_user_detection?: boolean;
  challenge_type?: string;
  captcha_challenge?: { cookie_expiry?: number; custom_page?: string };
  js_challenge?: { cookie_expiry?: number; custom_page?: string; js_script_delay?: number };
  policy_based_challenge?: {
    malicious_user_mitigation?: ObjectRef;
    captcha_challenge_parameters?: { cookie_expiry?: number };
    js_challenge_parameters?: { cookie_expiry?: number; js_script_delay?: number };
    rule_list?: { rules?: unknown[] };
    default_captcha_challenge_parameters?: boolean;
    default_js_challenge_parameters?: boolean;
    default_mitigation_settings?: boolean;
    no_challenge?: boolean;
    always_enable_captcha?: boolean;
    always_enable_js_challenge?: boolean;
  };
  enable_challenge?: {
    default_mitigation_settings?: unknown;
    default_js_challenge_parameters?: unknown;
    default_captcha_challenge_parameters?: unknown;
  };
  no_challenge?: boolean;
  single_lb_app?: { enable_discovery?: boolean; enable_ddos_detection?: boolean };
  multi_lb_app?: ObjectRef;
  waf_exclusion_rules?: WafExclusionRule[];
  waf_exclusion?: { waf_exclusion_inline_rules?: { rules?: unknown[] } };
  data_guard_rules?: DataGuardRule[];
  csrf_policy?: { allowed_domains?: { exact_value?: string; suffix_value?: string }[]; disabled?: boolean };
  cors_policy?: CorsPolicy;
  trusted_clients?: TrustedClient[];
  blocked_clients?: BlockedClient[];
  more_option?: MoreOptions;
  add_location?: boolean;
  round_robin?: unknown;
  least_active?: unknown;
  ring_hash?: unknown;
  random?: unknown;
  source_ip_stickiness?: unknown;
  cookie_stickiness_hash?: unknown;
  disable_trust_client_ip_headers?: unknown;
  enable_trust_client_ip_headers?: { client_ip_headers?: string[] };
  graphql_rules?: unknown[];
  protected_cookies?: ProtectedCookie[];
  system_default_timeouts?: unknown;
  disable_threat_mesh?: unknown;
  disable_malware_protection?: unknown;
  [key: string]: unknown;
}

export interface MoreOptions {
  request_headers_to_add?: Header[];
  request_headers_to_remove?: string[];
  response_headers_to_add?: Header[];
  response_headers_to_remove?: string[];
  max_request_header_size?: number;
  buffer_policy?: BufferPolicy;
  custom_errors?: Record<string, string>;
  idle_timeout?: number;
  disable_default_error_pages?: boolean;
  cookies_to_modify?: unknown[];
  request_cookies_to_add?: unknown[];
  request_cookies_to_remove?: string[];
  response_cookies_to_add?: unknown[];
  response_cookies_to_remove?: string[];
  javascript_info?: unknown;
  jwt?: unknown[];
}

export interface BufferPolicy {
  max_request_bytes?: number;
  max_request_time?: number;
  disabled?: boolean;
}

export interface RateLimitConfig {
  rate_limiter?: {
    unit?: string;
    total_number?: number;
    burst_multiplier?: number;
    period_multiplier?: number;
  };
  no_ip_allowed_list?: unknown;
  ip_allowed_list?: { prefixes?: string[] };
  no_policies?: unknown;
  policies?: ObjectRef[];
}

export interface L7DDoSProtection {
  mitigation_block?: unknown;
  mitigation_js_challenge?: unknown;
  mitigation_captcha?: unknown;
  default_rps_threshold?: unknown;
  custom_rps_threshold?: { threshold?: number };
  clientside_action_none?: unknown;
  clientside_action_block?: unknown;
  clientside_action_redirect?: unknown;
  ddos_policy_none?: unknown;
  ddos_policy?: ObjectRef;
}

export interface DDoSMitigationRule {
  metadata?: { name?: string };
  ddos_client_source?: { country_list?: string[]; asn_list?: { as_numbers?: number[] } };
  mitigation_action?: { none?: boolean; block?: boolean; js_challenge?: boolean };
}

export interface WafExclusionRule {
  metadata?: { name?: string };
  exact_value?: string;
  any_domain?: boolean;
  methods?: string[];
  path_regex?: string;
  app_firewall_detection_control?: {
    exclude_signature_contexts?: {
      signature_id?: string;
      context?: string;
      context_name?: string;
    }[];
    exclude_attack_type_contexts?: {
      attack_type?: string;
      context?: string;
      context_name?: string;
    }[];
    exclude_violation_contexts?: {
      violation_type?: string;
      context?: string;
      context_name?: string;
    }[];
  };
}

export interface DataGuardRule {
  metadata?: { name?: string };
  path?: { prefix?: string; regex?: string };
  apply_data_guard?: boolean;
  skip_data_guard?: boolean;
}

export interface CorsPolicy {
  allow_origin?: string[];
  allow_origin_regex?: string[];
  allow_methods?: string;
  allow_headers?: string;
  expose_headers?: string;
  max_age?: string;
  allow_credentials?: boolean;
  disabled?: boolean;
}

export interface TrustedClient {
  metadata?: { name?: string; disable?: boolean };
  ip_prefix?: string;
  as_number?: number;
  expiration_timestamp?: string;
  skip_processing?: string[];
  actions?: string[];
}

export interface BlockedClient {
  metadata?: { name?: string; disable?: boolean };
  ip_prefix?: string;
  as_number?: number;
  expiration_timestamp?: string;
  actions?: string[];
}

export interface ProtectedCookie {
  name: string;
  ignore_samesite?: unknown;
  samesite_strict?: unknown;
  samesite_lax?: unknown;
  samesite_none?: unknown;
  add_secure?: unknown;
  ignore_secure?: unknown;
  add_httponly?: unknown;
  ignore_httponly?: unknown;
  disable_tampering_protection?: unknown;
  enable_tampering_protection?: unknown;
}

export interface ObjectRef {
  name: string;
  namespace?: string;
}

export interface TLSConfig {
  tls_config?: {
    min_version?: string;
    max_version?: string;
    cipher_suites?: string[];
    tls_certificates?: TLSCertificate[];
    default_security?: unknown;
    low_security?: unknown;
    medium_security?: unknown;
    custom_security?: unknown;
  };
  tls_cert_params?: {
    tls_config?: {
      default_security?: unknown;
      low_security?: unknown;
      medium_security?: unknown;
      custom_security?: unknown;
    };
    certificates?: ObjectRef[];
    no_mtls?: unknown;
    use_mtls?: { client_certificate?: ObjectRef };
  };
  tls_certificates?: TLSCertificate[];
  mtls?: boolean;
  no_mtls?: boolean;
  http_redirect?: boolean;
  add_hsts?: boolean;
  default_header?: unknown;
  enable_path_normalize?: unknown;
  port?: number;
  connection_idle_timeout?: number;
  header_transformation_type?: {
    legacy_header_transformation?: unknown;
    proper_case_header_transformation?: unknown;
    preserve_case_header_transformation?: unknown;
  };
  http_protocol_options?: {
    http_protocol_enable_v1_only?: unknown;
    http_protocol_enable_v1_v2?: unknown;
    http_protocol_enable_v2_only?: unknown;
  };
  coalescing_options?: {
    default_coalescing?: unknown;
    disable_coalescing?: unknown;
    apply_coalescing?: { ttl?: number };
  };
  non_default_loadbalancer?: unknown;
  [key: string]: unknown;
}

export interface TLSCertificate {
  certificate_url?: string;
  description?: string;
  custom_hash_algorithms?: string[];
  private_key?: {
    clear_secret_info?: {
      provider?: string;
      url?: string;
    };
    blindfold_secret_info?: {
      decryption_provider?: string;
      location?: string;
    };
    secret_encoding_type?: string;
  };
}

export interface Header {
  name: string;
  value?: string;
}

export interface Route {
  simple_route?: SimpleRoute;
  redirect_route?: RedirectRoute;
  direct_response_route?: DirectResponseRoute;
  custom_route_object?: { route_ref?: ObjectRef };
}

export interface SimpleRoute {
  path?: {
    prefix?: string;
    regex?: string;
    path?: string;
  };
  http_method?: string | { methods: string[] };
  origin_pools?: PoolRef[];
  advanced_options?: RouteAdvancedOptions;
  headers?: unknown[];
  query_params?: { retain_all_params?: unknown; strip_query_params?: { query_params?: string[] } };
  incoming_port?: { no_port_match?: unknown; port_match?: { port?: number } };
  disable_host_rewrite?: unknown;
  auto_host_rewrite?: unknown;
  host_rewrite?: string;
  uuid?: string;
}

export interface RouteAdvancedOptions {
  app_firewall?: ObjectRef;
  disable_waf?: boolean;
  inherited_waf_exclusion?: unknown;
  request_timeout?: number;
  timeout?: number;
  retry_policy?: unknown;
  default_retry_policy?: unknown;
  cors_policy?: unknown;
  common_hash_policy?: unknown;
  priority?: string;
  endpoint_subsets?: unknown;
  disable_prefix_rewrite?: unknown;
  prefix_rewrite?: string;
  request_headers_to_add?: Header[];
  request_headers_to_remove?: string[];
  response_headers_to_add?: Header[];
  response_headers_to_remove?: string[];
  disable_location_add?: boolean;
  request_cookies_to_add?: unknown[];
  request_cookies_to_remove?: string[];
  response_cookies_to_add?: unknown[];
  response_cookies_to_remove?: string[];
  disable_spdy?: unknown;
  enable_spdy?: unknown;
  disable_web_socket_config?: unknown;
  enable_web_socket_config?: unknown;
  common_buffering?: unknown;
  buffer_policy?: BufferPolicy;
  disable_mirroring?: unknown;
  mirror_policy?: unknown;
  retract_cluster?: unknown;
  inherited_bot_defense_javascript_injection?: unknown;
  bot_defense_javascript_injection?: unknown;
}

export interface RedirectRoute {
  path?: { prefix?: string };
  host_redirect?: string;
  path_redirect?: string;
  response_code?: string;
}

export interface DirectResponseRoute {
  path?: { prefix?: string };
  response_code?: number;
  response_body?: string;
}

export interface PoolRef {
  pool?: ObjectRef;
  weight?: number;
  priority?: number;
}

export interface OriginPool {
  name: string;
  metadata?: { name: string; namespace: string };
  spec?: {
    origin_servers?: OriginServer[];
    port?: number;
    use_tls?: {
      use_host_header_as_sni?: unknown;
      sni?: string;
      tls_config?: {
        default_security?: unknown;
        low_security?: unknown;
        medium_security?: unknown;
        custom_security?: unknown;
      };
      skip_server_verification?: unknown;
      volterra_trusted_ca?: unknown;
      use_server_verification?: {
        trusted_ca_url?: string;
      };
      no_mtls?: unknown;
      use_mtls?: {
        tls_certificates?: Array<{
          certificate_url?: string;
          private_key?: {
            blindfold_secret_info?: {
              location?: string;
            };
          };
        }>;
      };
      default_session_key_caching?: unknown;
      disable_session_key_caching?: unknown;
    } | boolean;
    no_tls?: unknown;
    loadbalancer_algorithm?: string;
    healthcheck?: ObjectRef[];
    endpoint_selection?: string;
    advanced_options?: {
      connection_timeout?: number;
      http_idle_timeout?: number;
      http2_options?: {
        enabled?: boolean;
      };
      default_circuit_breaker?: unknown;
      circuit_breaker?: {
        max_connections?: number;
        max_pending_requests?: number;
        max_requests?: number;
        max_retries?: number;
      };
      disable_outlier_detection?: unknown;
      outlier_detection?: {
        consecutive_5xx?: number;
        consecutive_gateway_failure?: number;
        interval?: number;
        base_ejection_time?: number;
        max_ejection_percent?: number;
      };
      no_panic_threshold?: unknown;
      panic_threshold?: number;
      disable_subsets?: unknown;
      enable_subsets?: {
        endpoint_subsets?: Array<{
          keys?: string[];
        }>;
      };
      auto_http_config?: unknown;
      http1_config?: unknown;
      http2_config?: unknown;
      disable_lb_source_ip_persistance?: unknown;
      enable_lb_source_ip_persistance?: unknown;
      disable_proxy_protocol?: unknown;
      proxy_protocol_v1?: unknown;
      proxy_protocol_v2?: unknown;
    };
    upstream_conn_pool_reuse_type?: {
      enable_conn_pool_reuse?: unknown;
      disable_conn_pool_reuse?: unknown;
    };
  };
}

export interface SiteLocator {
  site?: ObjectRef;
  virtual_site?: ObjectRef & { tenant?: string; kind?: string };
}

export interface OriginServerPrivateIP {
  ip: string;
  site_locator?: SiteLocator;
  outside_network?: unknown;
  inside_network?: unknown;
  snat_pool?: unknown;
}

export interface OriginServerPrivateName {
  dns_name: string;
  site_locator?: SiteLocator;
  outside_network?: unknown;
  inside_network?: unknown;
  refresh_interval?: number;
}

export interface OriginServerK8s {
  service_name: string;
  site_locator?: SiteLocator;
  outside_network?: unknown;
  inside_network?: unknown;
  vk8s_networks?: unknown;
  service_selector?: {
    expressions?: string[];
  };
}

export interface OriginServer {
  public_ip?: { ip: string };
  public_name?: { dns_name: string; refresh_interval?: number };
  private_ip?: OriginServerPrivateIP;
  private_name?: OriginServerPrivateName;
  k8s_service?: OriginServerK8s;
  consul_service?: unknown;
  vn_private_ip?: unknown;
  labels?: Record<string, string>;
}

export interface VirtualSite {
  name?: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    description?: string;
    disable?: boolean;
  };
  system_metadata?: {
    uid?: string;
    creation_timestamp?: string;
    tenant?: string;
  };
  spec?: {
    site_selector?: {
      expressions?: string[];
    };
    site_type?: string;
  };
}

export interface WAFPolicy {
  name: string;
  metadata?: { name: string; namespace: string; disable?: boolean };
  shared?: boolean;
  spec?: {
    mode?: string;
    blocking?: unknown;
    monitoring?: unknown;
    ai_risk_based_blocking?: {
      high_risk_action?: string;
      medium_risk_action?: string;
      low_risk_action?: string;
    };
    detection_settings?: {
      signature_selection_setting?: {
        default_attack_type_settings?: unknown;
        high_medium_low_accuracy_signatures?: unknown;
        high_medium_accuracy_signatures?: unknown;
        only_high_accuracy_signatures?: unknown;
        attack_type_settings?: {
          disabled_attack_types?: string[];
        };
        signature_selection_by_accuracy?: {
          high_accuracy_signatures?: boolean;
          medium_accuracy_signatures?: boolean;
          low_accuracy_signatures?: boolean;
        };
      };
      enable_suppression?: unknown;
      disable_suppression?: unknown;
      enable_threat_campaigns?: unknown;
      disable_threat_campaigns?: unknown;
      stage_new_signatures?: {
        staging_period?: number;
      };
      disable_staging?: unknown;
      violation_settings?: {
        disabled_violation_types?: string[];
      };
      default_violation_settings?: unknown;
      bot_protection_setting?: {
        malicious_bot_action?: string;
        suspicious_bot_action?: string;
        good_bot_action?: string;
      };
    };
    bot_protection_setting?: {
      malicious_bot_action?: string;
      suspicious_bot_action?: string;
      good_bot_action?: string;
    };
    default_bot_setting?: unknown;
    allow_all_response_codes?: unknown;
    allowed_response_codes?: { response_code?: number[] };
    default_anonymization?: unknown;
    custom_anonymization?: { custom_sensitive_data_rules?: unknown[] };
    use_default_blocking_page?: unknown;
    blocking_page?: {
      response_code?: string;
      blocking_page?: string;
      blocking_page_body?: string;
    };
    use_loadbalancer_setting?: unknown;
    http_protocol_settings?: {
      max_header_name_length?: number;
      max_header_value_length?: number;
      max_headers?: number;
      max_url_length?: number;
      max_query_string_length?: number;
      max_request_body_size?: number;
      allow_unknown_content_types?: boolean;
      allowed_content_types?: string[];
    };
    graphql_settings?: {
      enabled?: boolean;
      max_depth?: number;
      max_batched_queries?: number;
      max_total_length?: number;
      max_value_length?: number;
    };
    data_leak_prevention_setting?: {
      credit_card_numbers?: string;
      us_social_security_numbers?: string;
      custom_patterns?: unknown[];
    };
    file_upload_restriction_setting?: {
      disable_file_upload?: boolean;
      allowed_file_types?: string[];
      max_file_size?: number;
    };
    cookie_protection_setting?: {
      add_secure_attribute?: boolean;
      add_samesite_attribute?: string;
      add_httponly_attribute?: boolean;
    };
  };
}

export interface HealthCheck {
  name: string;
  metadata?: { name: string; namespace: string };
  spec?: {
    http_health_check?: {
      path?: string;
      use_origin_server_name?: boolean;
      host_header?: string;
      expected_status_codes?: string[];
      request_headers_to_remove?: string[];
    };
    tcp_health_check?: unknown;
    timeout?: number;
    interval?: number;
    unhealthy_threshold?: number;
    healthy_threshold?: number;
    jitter_percent?: number;
  };
}

export interface ServicePolicy {
  name: string;
  metadata?: { name: string; namespace: string };
  spec?: {
    algo?: string;
    any_server?: boolean;
    server_selector?: {
      expressions?: string[];
    };
    server_name?: string;
    server_name_matcher?: {
      exact_values?: string[];
      regex_values?: string[];
    };
    rule_list?: {
      rules?: ServicePolicyRule[];
    };
    deny_list?: {
      rules?: ServicePolicyRule[];
    };
    allow_list?: {
      rules?: ServicePolicyRule[];
    };
    legacy_rule_list?: unknown;
  };
}

export interface ServicePolicyRule {
  metadata?: { name?: string; description?: string };
  spec?: {
    action?: string;
    any_client?: boolean;
    client_selector?: {
      expressions?: string[];
    };
    client_name?: string;
    client_name_matcher?: {
      exact_values?: string[];
      regex_values?: string[];
    };
    ip_prefix_list?: {
      prefixes?: string[];
      invert_match?: boolean;
    };
    asn_list?: {
      as_numbers?: number[];
    };
    asn_matcher?: {
      asn_sets?: { name?: string; namespace?: string }[];
    };
    tls_fingerprint_matcher?: {
      classes?: string[];
      exact_values?: string[];
      excluded_values?: string[];
    };
    label_matcher?: {
      keys?: string[];
    };
    any_ip?: boolean;
    waf_action?: {
      none?: boolean;
      waf_skip_processing?: boolean;
      waf_in_monitoring_mode?: boolean;
      waf_rule_control?: {
        exclude_rule_ids?: string[];
      };
      app_firewall_detection_control?: unknown;
    };
    bot_action?: {
      none?: boolean;
      bot_skip_processing?: boolean;
    };
    content_rewrite_action?: unknown;
    shape_protected_endpoint_action?: unknown;
    headers?: {
      name?: string;
      exact?: string;
      regex?: string;
      presence?: boolean;
      invert_matcher?: boolean;
    }[];
    query_params?: {
      key?: string;
      exact?: string;
      regex?: string;
      presence?: boolean;
      invert_matcher?: boolean;
    }[];
    path?: {
      prefix?: string;
      regex?: string;
      path?: string;
      transformers?: string[];
    };
    http_method?: {
      methods?: string[];
      invert_matcher?: boolean;
    };
    arg_matchers?: {
      name?: string;
      item?: { exact_values?: string[]; regex_values?: string[] };
      presence?: boolean;
      invert_matcher?: boolean;
    }[];
    cookie_matchers?: {
      name?: string;
      item?: { exact_values?: string[]; regex_values?: string[] };
      presence?: boolean;
      invert_matcher?: boolean;
    }[];
    domain_matcher?: {
      exact_values?: string[];
      regex_values?: string[];
    };
    challenge_action?: string;
    rate_limiter?: ObjectRef;
    go_to_policy?: ObjectRef;
    request_constraints?: {
      max_content_length?: number;
      content_types?: string[];
    };
  };
}

export interface ParsedRoute {
  index: number;
  type: 'simple' | 'redirect' | 'direct_response' | 'custom' | 'unknown';
  path: string;
  pathMatch: 'prefix' | 'regex' | 'exact';
  methods: string[];
  origins: Array<{
    name?: string;
    namespace?: string;
    weight?: number;
    priority?: number;
  }>;
  waf: { name?: string; namespace?: string; disabled?: boolean } | null;
  timeout?: number;
  retries?: unknown;
  corsPolicy?: unknown;
  headerMatchers?: unknown[];
  queryParams?: unknown[];
  redirectConfig?: { host?: string; path?: string; code?: string };
  directResponse?: { code?: number; body?: string };
  advancedOptions?: RouteAdvancedOptionsDisplay;
}

export interface RouteAdvancedOptionsDisplay {
  hostRewrite?: string | null;
  prefixRewrite?: string | null;
  webSocket?: boolean | null;
  spdy?: boolean | null;
  buffering?: unknown;
  mirroring?: unknown;
  locationAdd?: boolean;
  requestHeaders?: number;
  responseHeaders?: number;
  requestCookies?: number;
  responseCookies?: number;
  priority?: string;
  botDefense?: unknown;
}

export interface WAFScanRow {
  namespace: string;
  lb_name: string;
  route: string;
  waf_name: string;
  waf_mode: string;
  inherited?: boolean;
}

export interface ScanStats {
  namespaces: number;
  loadBalancers: number;
  routes: number;
  wafs: number;
}

export interface AppType {
  name?: string;
  namespace?: string;
  tenant?: string;
  uid?: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    disable?: boolean;
  };
  spec?: AppTypeSpec;
  get_spec?: AppTypeSpec;
  resource_version?: string;
}

export interface AppTypeSpec {
  features?: AppTypeFeature[];
  business_logic_markup_setting?: {
    enable?: unknown;
    disable?: unknown;
    discovered_api_settings?: {
      purge_duration_for_inactive_discovered_apis?: number;
    };
  };
  api_discovery_setting?: {
    disable_learn_from_redirect_traffic?: unknown;
    enable_learn_from_redirect_traffic?: unknown;
    discovered_api_settings?: {
      purge_duration_for_inactive_discovered_apis?: number;
    };
  };
  bot_defense_setting?: {
    regional_endpoint?: string;
    policy?: ObjectRef;
  };
  user_behavior_analysis_setting?: {
    enable_detection?: boolean;
    enable_learning?: boolean;
    cooldown_period?: number;
    include_failed_login?: boolean;
    include_forbidden_requests?: boolean;
    include_ip_reputation?: boolean;
    include_waf_data?: boolean;
  };
  malicious_user_detection?: unknown;
  malicious_user_mitigation?: ObjectRef;
  client_side_defense?: {
    policy?: ObjectRef;
  };
  timeseries_analyses_setting?: {
    metric_selectors?: {
      metric?: string[];
      metrics_source?: string;
    }[];
  };
}

export interface AppTypeFeature {
  type?: string;
  enabled?: boolean;
}

export interface AppSetting {
  name?: string;
  namespace?: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    disable?: boolean;
  };
  spec?: AppSettingSpec;
  get_spec?: AppSettingSpec;
}

export interface AppSettingSpec {
  app_type_refs?: ObjectRef[];
  app_type_settings?: AppTypeSetting[];
  anomaly_types?: string[];
  user_behavior_analysis_setting?: {
    enable_detection?: boolean;
    enable_learning?: boolean;
    cooldown_period?: number;
    include_failed_login?: boolean;
    include_forbidden_requests?: boolean;
    include_ip_reputation?: boolean;
    include_waf_data?: boolean;
  };
  malicious_user_mitigation?: ObjectRef;
  timeseries_analyses_setting?: {
    metric_selectors?: {
      metric?: string[];
      metrics_source?: string;
    }[];
  };
}

export interface UserIdentificationPolicy {
  name: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    description?: string;
    disable?: boolean;
  };
  spec?: UserIdentificationPolicySpec;
  get_spec?: UserIdentificationPolicySpec;
}

export interface UserIdentificationPolicySpec {
  rules?: UserIdentificationRule[];
}

export interface UserIdentificationRule {
  ip_and_ja4_tls_fingerprint?: unknown;
  ip_and_tls_fingerprint?: unknown;
  client_ip?: unknown;
  tls_fingerprint?: unknown;
  ja4_tls_fingerprint?: unknown;
  http_header?: { name?: string };
  http_cookie?: { name?: string };
  none?: unknown;
  client_identifier?: {
    ip_and_ja4_tls_fingerprint?: unknown;
    ip_and_tls_fingerprint?: unknown;
    client_ip?: unknown;
    tls_fingerprint?: unknown;
    ja4_tls_fingerprint?: unknown;
    http_header?: { name?: string };
    http_cookie?: { name?: string };
    none?: unknown;
  };
}

export interface AppTypeSetting {
  app_type_ref?: ObjectRef;
  business_logic_markup_setting?: {
    enable?: unknown;
    disable?: unknown;
    discovered_api_settings?: {
      purge_duration_for_inactive_discovered_apis?: number;
    };
  };
  timeseries_analyses_setting?: {
    metric_selectors?: {
      metric?: string[];
      metrics_source?: string;
    }[];
  };
  user_behavior_analysis_setting?: {
    enable_detection?: boolean;
    enable_learning?: boolean;
    cooldown_period?: number;
    include_failed_login?: boolean;
    include_forbidden_requests?: boolean;
    include_ip_reputation?: boolean;
    include_waf_data?: boolean;
  };
}

// ... (Keep all your existing interfaces)

// --- NEW CDN INTERFACES ---

export interface CDNLoadBalancer {
  name: string;
  namespace?: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    disable?: boolean;
    description?: string;
  };
  system_metadata?: {
    creation_timestamp: string;
  };
  spec?: CDNLoadBalancerSpec;
}

export interface CDNLoadBalancerSpec {
  domains?: string[];
  https_auto_cert?: TLSConfig;
  https?: TLSConfig;
  http_redirect?: boolean;
  add_location?: boolean;
  origin_pool?: ObjectRef;
  app_firewall?: ObjectRef;
  bot_defense?: {
    policy?: ObjectRef;
    regional_endpoint?: string;
  };
  disable_bot_defense?: boolean;
  cdn_settings?: CDNSettings;
  // Common fields shared with LB might appear here depending on config
  [key: string]: unknown;
}

export interface CDNSettings {
  default_cache_behavior?: string;
  max_cache_size?: number; // in MB
  cache_ttl?: number; // in seconds
  cache_rules?: ObjectRef[];
}

export interface CDNCacheRule {
  name: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    description?: string;
  };
  spec?: {
    priority?: number;
    path?: {
      prefix?: string;
      regex?: string;
      exact?: string;
    };
    format_caching?: unknown;
    query_params_caching?: {
      include_all?: boolean;
      include_list?: string[];
      exclude_list?: string[];
    };
    cache_ttl?: number;
    browser_ttl?: number;
    ignore_origin_cache_control?: boolean;
  };
}

export interface Certificate {
  metadata: {
    name: string;
    namespace: string;
    disable?: boolean;
    description?: string;
  };
  system_metadata: {
    creation_timestamp?: string;
    creator_id?: string;
  };
  spec: {
    certificate_url: string;
    private_key?: {
      blindfold_secret_info_internal?: any;
      clear_secret_info?: { provider?: string };
    };
    // Updated to match your JSON structure
    infos?: Array<{
      common_name?: string;
      issuer?: string;
      expiry?: string;    // <--- Found in your JSON
      not_after?: string; // Legacy/Alt field
      serial_number?: string;
      subject_alternative_names?: string[]; // <--- Found in your JSON
      public_key_algorithm?: string;
    }>;
  };
}

export interface ParsedCertificateSubject {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

export interface ParsedCertificate {
  subject: ParsedCertificateSubject;
  issuer: ParsedCertificateSubject;
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  sans: string[];
  isSelfSigned: boolean;
  fingerprint?: string;
}

// --- Alert Receiver & Policy Types ---

export interface AlertReceiver {
  name?: string;
  namespace?: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    description?: string;
    disable?: boolean;
  };
  system_metadata?: {
    uid?: string;
    creation_timestamp?: string;
    modification_timestamp?: string;
    creator_id?: string;
    tenant?: string;
  };
  spec?: AlertReceiverSpec;
  get_spec?: AlertReceiverSpec;
}

export interface AlertReceiverSpec {
  // Receiver type - one of these will be set
  slack?: {
    url?: {
      blindfold_secret_info?: {
        location?: string;
        decryption_provider?: string;
      };
      clear_secret_info?: {
        url?: string;
        provider?: string;
      };
      vault_secret_info?: unknown;
      wingman_secret_info?: unknown;
    };
    channel?: string;
  };
  pagerduty?: {
    url?: {
      blindfold_secret_info?: {
        location?: string;
        decryption_provider?: string;
      };
      clear_secret_info?: {
        url?: string;
        provider?: string;
      };
    };
    routing_key?: {
      blindfold_secret_info?: {
        location?: string;
        decryption_provider?: string;
      };
      clear_secret_info?: {
        url?: string;
        provider?: string;
      };
    };
  };
  opsgenie?: {
    url?: {
      blindfold_secret_info?: unknown;
      clear_secret_info?: unknown;
    };
    api_key?: {
      blindfold_secret_info?: unknown;
      clear_secret_info?: unknown;
    };
  };
  email?: {
    email?: string;
  };
  sms?: {
    contact_number?: string;
  };
  webhook?: {
    webhook_url?: {
      blindfold_secret_info?: {
        location?: string;
        decryption_provider?: string;
      };
      clear_secret_info?: {
        url?: string;
        provider?: string;
      };
    };
    http_configuration?: {
      no_authentication?: unknown;
      basic_authentication?: {
        user_name?: string;
        password?: {
          blindfold_secret_info?: unknown;
          clear_secret_info?: unknown;
        };
      };
      bearer_token?: {
        token?: {
          blindfold_secret_info?: unknown;
          clear_secret_info?: unknown;
        };
      };
    };
  };
  none?: unknown;
}

export interface AlertPolicy {
  name?: string;
  namespace?: string;
  metadata?: {
    name: string;
    namespace: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    description?: string;
    disable?: boolean;
  };
  system_metadata?: {
    uid?: string;
    creation_timestamp?: string;
    modification_timestamp?: string;
    creator_id?: string;
    tenant?: string;
  };
  spec?: AlertPolicySpec;
  get_spec?: AlertPolicySpec;
}

export interface AlertPolicySpec {
  receivers?: Array<{
    name?: string;
    namespace?: string;
  }>;
  notification_parameters?: {
    group_wait?: string;
    group_interval?: string;
    repeat_interval?: string;
  };
  notification_grouping?: {
    group_by?: string[];
    group_by_alert_fields?: unknown;
    group_by_labels?: unknown;
  };
  routes?: AlertPolicyRoute[];
}

export interface AlertPolicyRoute {
  match?: {
    any?: unknown;
    all_alerts?: unknown;
    custom_alert_criteria?: {
      alert_name?: {
        exact_values?: string[];
        regex_values?: string[];
      };
      group_name?: {
        exact_values?: string[];
        regex_values?: string[];
      };
      severity?: {
        severities?: string[];
      };
      additional_label_matchers?: Array<{
        label_name?: string;
        label_values?: {
          exact_values?: string[];
          regex_values?: string[];
        };
      }>;
    };
  };
  action?: {
    send?: unknown;
    drop?: unknown;
  };
  receivers?: Array<{
    name?: string;
    namespace?: string;
  }>;
  notification_parameters?: {
    group_wait?: string;
    group_interval?: string;
    repeat_interval?: string;
  };
  notification_grouping?: {
    group_by?: string[];
    group_by_alert_fields?: unknown;
    group_by_labels?: unknown;
  };
}

// --- Config Object Types for Copy Config Tool ---

export type ConfigObjectType = 'alert_receiver' | 'alert_policy';

export interface ConfigObjectInfo {
  type: ConfigObjectType;
  name: string;
  displayName: string;
  apiPath: string;
  apiPathPlural: string;
}

export const CONFIG_OBJECT_TYPES: Record<ConfigObjectType, ConfigObjectInfo> = {
  alert_receiver: {
    type: 'alert_receiver',
    name: 'alert_receiver',
    displayName: 'Alert Receiver',
    apiPath: 'alert_receivers',
    apiPathPlural: 'alert_receivers',
  },
  alert_policy: {
    type: 'alert_policy',
    name: 'alert_policy',
    displayName: 'Alert Policy',
    apiPath: 'alert_policys',
    apiPathPlural: 'alert_policys',
  },
};
