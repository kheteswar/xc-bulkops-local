// =============================================================================
// Live SOC Monitoring Room — Incident Manager
// =============================================================================
// Manages the lifecycle of incidents:
//   - Create new incidents for anomalies not yet linked to an incident
//   - Update existing incidents: add new anomaly IDs, escalate severity
//   - Auto-resolve incidents when all linked anomalies are resolved
//   - Group related anomalies into the same incident
// =============================================================================

import type {
  Anomaly,
  AnomalySeverity,
  Incident,
  IncidentStatus,
  DetectorId,
} from './types';

// =============================================================================
// Grouping Rules
// =============================================================================

/**
 * Defines which detector IDs should be grouped into the same incident.
 * When multiple anomalies from the same group fire simultaneously,
 * they are linked to a single incident rather than creating separate ones.
 *
 * Groups based on root cause correlation:
 */
const ANOMALY_GROUPS: DetectorId[][] = [
  // Traffic surge group: RPS spike + WAF surge + Bot surge + Sample rate surge
  [1, 5, 10, 15, 16],
  // Origin failure group: RPS drop + 5xx spike + Origin down + Latency spike
  [2, 3, 8, 7],
  // Security attack group: WAF surge + New signature + Threat mesh + Credential stuffing
  [5, 6, 12, 17],
  // DNS/Infra group: DNS degradation + Network DDoS + Synthetic fail
  [19, 22, 18],
  // Bot group: Bot surge (AL) + Bot surge (BD) + Credential stuffing
  [10, 16, 17],
  // CDN group: CDN cache degradation (standalone)
  [13],
  // Config group: Config change + 4xx spike (could be related)
  [14, 4],
  // Client-side: CSD alert
  [20],
  // API Security: API vulnerability
  [23],
  // WAF Signature: WAF sig update
  [21],
  // Rate limit: Rate limit fire
  [11],
];

/**
 * Finds the group index for a given detector ID.
 * Returns -1 if no group contains this detector.
 */
function findGroupIndex(detectorId: DetectorId): number {
  for (let i = 0; i < ANOMALY_GROUPS.length; i++) {
    if (ANOMALY_GROUPS[i].includes(detectorId)) {
      return i;
    }
  }
  return -1;
}

// =============================================================================
// ID Generation
// =============================================================================

function generateIncidentId(): string {
  return 'INC-' + Date.now().toString(36) + Math.random().toString(36).substring(2, 6);
}

// =============================================================================
// Incident Title Generation
// =============================================================================

/**
 * Generates a human-readable incident title from its linked anomalies.
 */
function generateTitle(anomalies: Anomaly[]): string {
  if (anomalies.length === 0) return 'Unknown Incident';
  if (anomalies.length === 1) return anomalies[0].detectorName;

  // Find the highest severity anomaly as the primary
  const sorted = [...anomalies].sort((a, b) => {
    const order: Record<AnomalySeverity, number> = {
      INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
    };
    return order[b.severity] - order[a.severity];
  });

  const primary = sorted[0].detectorName;
  const others = sorted.length - 1;

  return `${primary} (+${others} related)`;
}

/**
 * Generates a summary description from linked anomalies.
 */
function generateSummary(anomalies: Anomaly[]): string {
  if (anomalies.length === 0) return '';

  const messages = anomalies.map((a) => `[${a.severity}] ${a.message}`);
  return messages.join('; ');
}

// =============================================================================
// Severity Helpers
// =============================================================================

/**
 * Returns the maximum severity across a set of anomalies.
 */
function maxSeverity(anomalies: Anomaly[]): AnomalySeverity {
  const order: Record<AnomalySeverity, number> = {
    INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
  };
  const reverseOrder: AnomalySeverity[] = ['INFO', 'MEDIUM', 'HIGH', 'CRITICAL'];

  let maxIdx = 0;
  for (const a of anomalies) {
    const idx = order[a.severity];
    if (idx > maxIdx) maxIdx = idx;
  }
  return reverseOrder[maxIdx];
}

/**
 * Returns the higher of two severity levels.
 */
function severityMax(a: AnomalySeverity, b: AnomalySeverity): AnomalySeverity {
  const order: Record<AnomalySeverity, number> = {
    INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
  };
  return order[a] >= order[b] ? a : b;
}

// =============================================================================
// Main Reconciliation
// =============================================================================

/**
 * Reconciles active anomalies with existing incidents.
 *
 * Logic:
 * 1. For each active anomaly, check if it's already linked to an existing incident.
 * 2. If not linked, check if a related anomaly (same group) has an incident.
 *    - If yes, add this anomaly to that incident.
 *    - If no, create a new incident.
 * 3. Update existing incidents: escalate severity, refresh summary.
 * 4. Auto-resolve incidents where ALL linked anomalies are resolved.
 *
 * @param activeAnomalies - Current active (unresolved) anomalies
 * @param existingIncidents - All current incidents (active and resolved)
 * @returns Updated incident list
 */
export function reconcileIncidents(
  activeAnomalies: Anomaly[],
  existingIncidents: Incident[]
): Incident[] {
  const now = new Date().toISOString();
  const incidents = existingIncidents.map((inc) => ({ ...inc }));

  // Build a lookup: anomaly ID → incident ID
  const anomalyToIncident = new Map<string, string>();
  for (const inc of incidents) {
    for (const aId of inc.anomalyIds) {
      anomalyToIncident.set(aId, inc.id);
    }
  }

  // Build a lookup: group index → incident ID (from active incidents only)
  const groupToIncident = new Map<number, string>();
  for (const inc of incidents) {
    if (inc.status === 'resolved') continue;

    // Find any anomaly in this incident to determine the group
    for (const aId of inc.anomalyIds) {
      const anomaly = activeAnomalies.find((a) => a.id === aId);
      if (anomaly) {
        const groupIdx = findGroupIndex(anomaly.detectorId);
        if (groupIdx >= 0 && !groupToIncident.has(groupIdx)) {
          groupToIncident.set(groupIdx, inc.id);
        }
      }
    }
  }

  // Process each active anomaly
  for (const anomaly of activeAnomalies) {
    if (anomaly.resolved) continue;

    // Skip if already linked to an incident
    if (anomalyToIncident.has(anomaly.id)) continue;

    const groupIdx = findGroupIndex(anomaly.detectorId);

    // Check if a related anomaly already has an incident
    let targetIncidentId: string | null = null;

    if (groupIdx >= 0) {
      targetIncidentId = groupToIncident.get(groupIdx) ?? null;
    }

    if (targetIncidentId) {
      // Add to existing incident
      const incident = incidents.find((inc) => inc.id === targetIncidentId);
      if (incident && !incident.anomalyIds.includes(anomaly.id)) {
        incident.anomalyIds.push(anomaly.id);
        incident.severity = severityMax(incident.severity, anomaly.severity);
      }
      anomalyToIncident.set(anomaly.id, targetIncidentId);
    } else {
      // Create new incident
      const newIncident: Incident = {
        id: generateIncidentId(),
        title: anomaly.detectorName,
        severity: anomaly.severity,
        status: 'active',
        anomalyIds: [anomaly.id],
        investigationIds: [],
        createdAt: now,
        summary: anomaly.message,
      };

      incidents.push(newIncident);
      anomalyToIncident.set(anomaly.id, newIncident.id);

      if (groupIdx >= 0) {
        groupToIncident.set(groupIdx, newIncident.id);
      }
    }
  }

  // Update and auto-resolve incidents
  for (const incident of incidents) {
    if (incident.status === 'resolved') continue;

    // Gather the anomalies linked to this incident
    const linkedAnomalies = activeAnomalies.filter((a) =>
      incident.anomalyIds.includes(a.id)
    );

    const activeLinked = linkedAnomalies.filter((a) => !a.resolved);

    if (activeLinked.length === 0) {
      // All linked anomalies are resolved or gone — auto-resolve
      incident.status = 'resolved';
      incident.resolvedAt = now;
    } else {
      // Update severity (may escalate or de-escalate)
      incident.severity = maxSeverity(activeLinked);

      // Update title and summary with current anomalies
      incident.title = generateTitle(activeLinked);
      incident.summary = generateSummary(activeLinked);

      // If any investigation is running, mark as investigating
      if (incident.investigationIds.length > 0) {
        incident.status = 'investigating';
      }
    }
  }

  return incidents;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Links an investigation to an incident.
 * Called when an investigation is spawned for an anomaly.
 */
export function linkInvestigationToIncident(
  incidents: Incident[],
  anomalyId: string,
  investigationId: string
): Incident[] {
  return incidents.map((inc) => {
    if (inc.anomalyIds.includes(anomalyId)) {
      const updatedInvIds = inc.investigationIds.includes(investigationId)
        ? inc.investigationIds
        : [...inc.investigationIds, investigationId];
      return {
        ...inc,
        investigationIds: updatedInvIds,
        status: 'investigating' as IncidentStatus,
      };
    }
    return inc;
  });
}

/**
 * Returns only active (non-resolved) incidents.
 */
export function getActiveIncidents(incidents: Incident[]): Incident[] {
  return incidents.filter((inc) => inc.status !== 'resolved');
}

/**
 * Returns the count of active incidents by severity.
 */
export function countIncidentsBySeverity(
  incidents: Incident[]
): Record<AnomalySeverity, number> {
  const counts: Record<AnomalySeverity, number> = {
    INFO: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };

  for (const inc of incidents) {
    if (inc.status !== 'resolved') {
      counts[inc.severity]++;
    }
  }

  return counts;
}

/**
 * Returns the most severe active incident, or null if none.
 */
export function getMostSevereIncident(incidents: Incident[]): Incident | null {
  const active = getActiveIncidents(incidents);
  if (active.length === 0) return null;

  const order: Record<AnomalySeverity, number> = {
    INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
  };

  return active.reduce((worst, inc) =>
    order[inc.severity] > order[worst.severity] ? inc : worst
  );
}

/**
 * Prunes old resolved incidents beyond a max count.
 * Keeps the most recent resolved incidents.
 */
export function pruneResolvedIncidents(
  incidents: Incident[],
  maxResolved: number = 200
): Incident[] {
  const active = incidents.filter((inc) => inc.status !== 'resolved');
  const resolved = incidents
    .filter((inc) => inc.status === 'resolved')
    .sort((a, b) => {
      const tA = new Date(a.resolvedAt ?? a.createdAt).getTime();
      const tB = new Date(b.resolvedAt ?? b.createdAt).getTime();
      return tB - tA; // Most recent first
    })
    .slice(0, maxResolved);

  return [...active, ...resolved];
}
