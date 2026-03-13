/**
 * Matching Info Analyzer
 *
 * Classifies WAF signature matching_info values as clearly malicious,
 * clearly benign, or ambiguous. Used to color-code matching info in the UI
 * and inform human review.
 */

export type MatchingInfoClassification = 'clearly_malicious' | 'clearly_benign' | 'ambiguous';

export interface MatchingInfoResult {
  classification: MatchingInfoClassification;
  reason: string;
}

// ─── Malicious Patterns ───
const MALICIOUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\/etc\/passwd/i, reason: 'Path traversal to /etc/passwd' },
  { pattern: /\/etc\/shadow/i, reason: 'Path traversal to /etc/shadow' },
  { pattern: /\.\.\/\.\.\//i, reason: 'Directory traversal sequence' },
  { pattern: /\.\.\\\.\.\\/, reason: 'Windows directory traversal' },
  { pattern: /php:\/\//i, reason: 'PHP stream wrapper' },
  { pattern: /data:text\/html/i, reason: 'Data URI XSS' },
  { pattern: /javascript:/i, reason: 'JavaScript protocol URI' },
  { pattern: /<script[\s>]/i, reason: 'Script injection tag' },
  { pattern: /on(error|load|click|mouseover|focus)\s*=/i, reason: 'Event handler injection' },
  { pattern: /union\s+(all\s+)?select/i, reason: 'SQL UNION injection' },
  { pattern: /;\s*(drop|delete|update|insert)\s/i, reason: 'SQL injection statement' },
  { pattern: /'\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, reason: 'SQL boolean injection' },
  { pattern: /exec\s*\(/i, reason: 'Code execution attempt' },
  { pattern: /eval\s*\(/i, reason: 'Dynamic code evaluation' },
  { pattern: /system\s*\(/i, reason: 'System command execution' },
  { pattern: /cmd\.exe|\/bin\/sh|\/bin\/bash/i, reason: 'Shell command injection' },
  { pattern: /\$\{.*\}/i, reason: 'Template/expression injection (${})' },
  { pattern: /\{\{.*\}\}/i, reason: 'Template injection ({{}})' },
  { pattern: /%00/i, reason: 'Null byte injection' },
  { pattern: /\x00/, reason: 'Null byte in value' },
];

// ─── Benign Patterns ───
const BENIGN_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /^[a-zA-Z0-9_-]{1,50}$/, reason: 'Simple alphanumeric value' },
  { pattern: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i, reason: 'UUID format' },
  { pattern: /^[a-zA-Z0-9+/]+=*$/, reason: 'Base64-encoded value' },
  { pattern: /^\d+$/, reason: 'Pure numeric ID' },
  { pattern: /^\d+\.\d+\.\d+$/, reason: 'Version number' },
  { pattern: /^[a-zA-Z][a-zA-Z0-9_.]*\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)$/i, reason: 'Static asset filename' },
  { pattern: /^(true|false|null|undefined|none)$/i, reason: 'Boolean/null literal' },
  { pattern: /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i, reason: 'HTTP method' },
  { pattern: /^(application|text|image|font|audio|video)\//i, reason: 'Content-Type value' },
  { pattern: /^[a-zA-Z]{2,10}$/, reason: 'Single common word' },
];

/**
 * Classify a matching_info value as clearly malicious, clearly benign,
 * or ambiguous.
 */
export function classifyMatchingInfo(value: string): MatchingInfoResult {
  if (!value || value.trim().length === 0) {
    return { classification: 'ambiguous', reason: 'Empty value' };
  }

  const trimmed = value.trim();

  // Check malicious patterns first
  for (const { pattern, reason } of MALICIOUS_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { classification: 'clearly_malicious', reason };
    }
  }

  // Check benign patterns
  for (const { pattern, reason } of BENIGN_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { classification: 'clearly_benign', reason };
    }
  }

  // Heuristic: short values (< 20 chars) with no special chars are likely benign
  if (trimmed.length < 20 && /^[a-zA-Z0-9._\-/]+$/.test(trimmed)) {
    return { classification: 'clearly_benign', reason: 'Short value with safe characters' };
  }

  // Heuristic: long values with many special chars are suspicious
  const specialCount = (trimmed.match(/[<>'"`;|&${}()\\]/g) || []).length;
  if (specialCount >= 3) {
    return { classification: 'clearly_malicious', reason: `Contains ${specialCount} special characters` };
  }

  return { classification: 'ambiguous', reason: 'Does not match known patterns' };
}
