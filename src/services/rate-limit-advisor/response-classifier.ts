import type { AccessLogEntry, ResponseOrigin } from './types';

/**
 * Known rsp_code_details values that indicate F5 XC actively blocked/rejected the request.
 * Everything else (via_upstream, timeouts, resets, etc.) is origin-related.
 */
const F5_BLOCK_PATTERNS = [
  'rate_limited',
  'blocked',
  'rejected',
  'denied',
  'waf',
  'bot_defense',
  'challenge',
  'captcha',
  'service_policy',
  'ip_reputation',
  'geo_blocked',
  'ddos',
  'malicious',
];

/**
 * Classifies an access log entry as origin-generated or F5 XC-blocked.
 *
 * - "via_upstream" = definitely from origin
 * - Known F5 block patterns = definitely F5 blocked
 * - Timeouts, resets, connection errors = still origin-related (not F5 blocking)
 * - Empty/missing = treat as origin (conservative — don't over-count blocks)
 */
export function classifyResponse(log: AccessLogEntry): ResponseOrigin {
  const details = (log.rsp_code_details || '').toLowerCase();

  // Explicit origin response
  if (details === 'via_upstream') return 'origin';

  // Check for known F5 block patterns
  for (const pattern of F5_BLOCK_PATTERNS) {
    if (details.includes(pattern)) return 'f5_blocked';
  }

  // Response code 0 with no upstream info = F5 intercepted
  if (log.rsp_code === '0' && !details.includes('upstream')) return 'f5_blocked';

  // Everything else (timeouts, resets, empty, etc.) = origin-related
  return 'origin';
}

/**
 * Secondary validation for edge cases.
 */
export function isDefinitelyF5Blocked(log: AccessLogEntry): boolean {
  const details = (log.rsp_code_details || '').toLowerCase();
  return F5_BLOCK_PATTERNS.some(p => details.includes(p));
}

/** Count of diagnostic logs emitted (limit to avoid flood) */
let _diagCount = 0;
const _DIAG_LIMIT = 5;

/** Try to extract a numeric HTTP status code from a log entry */
function extractStatusCode(log: Record<string, unknown>): number {
  // Try known field names for status code
  for (const key of ['rsp_code', 'response_code', 'status_code', 'status', 'http_status_code', 'rspCode', 'statusCode', 'code']) {
    const val = log[key];
    if (val !== undefined && val !== null && val !== '') {
      const code = typeof val === 'number' ? val : parseInt(String(val), 10);
      if (isFinite(code) && code >= 100 && code < 600) return code;
    }
  }

  // Diagnostic: log why extraction failed (first N entries only)
  if (_diagCount < _DIAG_LIMIT) {
    _diagCount++;
    const tried: Record<string, string> = {};
    for (const key of ['rsp_code', 'response_code', 'status_code', 'status', 'http_status_code', 'rspCode', 'statusCode', 'code']) {
      const val = log[key];
      tried[key] = val === undefined ? 'undefined' : val === null ? 'null' : `${JSON.stringify(val)} (type=${typeof val}, parseInt=${parseInt(String(val), 10)})`;
    }
    console.warn(`[DIAG-Classifier] extractStatusCode FAILED (entry ${_diagCount}/${_DIAG_LIMIT}):`, tried);
  }
  return 0;
}

/** Try to extract a response code class string (e.g. "2xx") from a log entry */
function extractStatusClass(log: Record<string, unknown>): string {
  for (const key of ['rsp_code_class', 'response_code_class', 'status_class', 'rspCodeClass']) {
    const val = log[key];
    if (val && typeof val === 'string' && /^[1-5]/.test(val)) return val.toLowerCase();
  }
  return '';
}

/**
 * Categorize the response code for the breakdown display.
 * Scans multiple field names for robustness against API field name variations.
 */
export function getResponseCategory(log: AccessLogEntry, origin: ResponseOrigin): string {
  if (origin === 'f5_blocked') {
    return 'f5_blocked';
  }

  const entry = log as unknown as Record<string, unknown>;

  // Try extracting numeric status code from multiple field names
  const code = extractStatusCode(entry);
  if (code >= 200 && code < 300) return 'origin_2xx';
  if (code >= 300 && code < 400) return 'origin_3xx';
  if (code >= 400 && code < 500) return 'origin_4xx';
  if (code >= 500 && code < 600) return 'origin_5xx';
  if (code >= 100 && code < 200) return 'origin_other';

  // Fallback: try code class fields (e.g., "2xx", "4xx")
  const codeClass = extractStatusClass(entry);
  if (codeClass.startsWith('2')) return 'origin_2xx';
  if (codeClass.startsWith('3')) return 'origin_3xx';
  if (codeClass.startsWith('4')) return 'origin_4xx';
  if (codeClass.startsWith('5')) return 'origin_5xx';

  // Diagnostic: log when falling through to origin_other
  if (_diagCount <= _DIAG_LIMIT) {
    console.warn(`[DIAG-Classifier] getResponseCategory → origin_other. extractStatusCode returned 0, extractStatusClass returned "${extractStatusClass(entry)}"`);
  }
  return 'origin_other';
}
