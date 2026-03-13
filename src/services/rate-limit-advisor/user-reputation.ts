import type { SecurityEventEntry, UserReputationType, UserSecurityDetails } from './types';

export interface ReputationEntry {
  reputation: UserReputationType;
  details: UserSecurityDetails;
}

/**
 * Builds a reputation map from security events.
 * For each unique user identifier, counts security events by type and assigns reputation:
 *   MALICIOUS: action="block" in ANY security event, OR bot_info.classification="malicious"
 *   FLAGGED: has security events with action="allow" + recommended_action="report"
 *   BENIGN_BOT: bot_info.classification="benign"
 *   CLEAN: no security events
 */
export function buildUserReputationMap(
  securityEvents: SecurityEventEntry[]
): Map<string, ReputationEntry> {
  const userMap = new Map<string, UserSecurityDetails>();

  for (const event of securityEvents) {
    const userId = event.user || event.src_ip || 'unknown';
    if (!userMap.has(userId)) {
      userMap.set(userId, {
        wafBlockCount: 0,
        wafReportCount: 0,
        botClassification: '',
        botName: '',
        svcPolicyBlockCount: 0,
        apiViolationCount: 0,
        attackTypes: [],
      });
    }

    const details = userMap.get(userId)!;

    // Count by event type
    if (event.sec_event_type === 'waf_sec_event') {
      if (event.action === 'block') {
        details.wafBlockCount++;
      } else if (event.recommended_action === 'report' || event.waf_mode === 'report') {
        details.wafReportCount++;
      }
    } else if (event.sec_event_type === 'svc_policy_sec_event') {
      if (event.action === 'block') {
        details.svcPolicyBlockCount++;
      }
    } else if (event.sec_event_type === 'api_sec_event') {
      details.apiViolationCount++;
    }

    // Bot info
    const botClass = event['bot_info.classification'] as string;
    const botName = event['bot_info.name'] as string;
    if (botClass && botClass !== 'UNKNOWN') {
      details.botClassification = botClass;
    }
    if (botName && botName !== 'UNKNOWN') {
      details.botName = botName;
    }

    // Attack types (from WAF events)
    const attackTypes = event['attack_types'] as string;
    if (attackTypes && typeof attackTypes === 'string' && !details.attackTypes.includes(attackTypes)) {
      details.attackTypes.push(attackTypes);
    }
  }

  // Convert to reputation entries
  const reputationMap = new Map<string, ReputationEntry>();

  for (const [userId, details] of userMap.entries()) {
    let reputation: UserReputationType = 'clean';

    if (
      details.wafBlockCount > 0 ||
      details.svcPolicyBlockCount > 0 ||
      details.botClassification === 'malicious'
    ) {
      reputation = 'malicious';
    } else if (details.botClassification === 'benign') {
      reputation = 'benign_bot';
    } else if (
      details.wafReportCount > 0 ||
      details.apiViolationCount > 0 ||
      details.botClassification === 'suspicious'
    ) {
      reputation = 'flagged';
    }

    reputationMap.set(userId, { reputation, details });
  }

  return reputationMap;
}

/**
 * Get reputation for a user from the access log's bot_class field.
 * Used when user has no security events but has bot classification in access logs.
 */
export function getReputationFromBotClass(botClass: string): UserReputationType | null {
  if (!botClass) return null;
  const lower = botClass.toLowerCase();
  if (lower === 'malicious') return 'malicious';
  if (lower === 'suspicious') return null; // Ignore — not reliable enough to flag
  if (lower === 'benign') return 'benign_bot';
  return null;
}
