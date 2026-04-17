// =============================================================================
// Live SOC Monitoring Room — Public Exports
// =============================================================================

// Types
export * from './types';

// Room storage
export { getRooms, saveRoom, deleteRoom, getRoomById, getBaseline, saveBaseline, getLastRoomId, setLastRoomId } from './room-storage';

// Error diagnosis KB
export { ERROR_DIAGNOSIS_KB, diagnoseError, classifyLatencyBottleneck } from './error-diagnosis';

// Sample rate utilities
export { extractAvgSampleRate, isSampleRateSurge, estimateActualCount } from './sample-rate';

// History buffer
export { RingBuffer, createTimeSeriesBuffer, createSnapshotBuffer, createEventBuffer } from './history-buffer';

// Aggregation query builders
export { buildAccessLogAggregations, buildSecurityEventAggregations, buildLBQuery, buildAllAggregations, computeTimeWindow } from './aggregation-builder';

// Metrics calculator
export { calculateMetrics, parseAggregationResponse } from './metrics-calculator';

// Raw log processor
export { processRawLogs } from './raw-log-processor';

// Alert fetcher
export { fetchActiveAlerts } from './alert-fetcher';

// Config change tracker
export { fetchRecentChanges, correlateWithAnomaly } from './config-change-tracker';

// Anomaly detection
export { evaluateDetectors, updateBaseline, computeThreatLevel } from './anomaly-detector';

// Incident management
export { reconcileIncidents } from './incident-manager';

// Investigation engine
export { createInvestigation, executeInvestigation } from './investigation-engine';

// Investigation chains
export { CHAIN_TRIGGERS, evaluateChains } from './investigation-chains';

// Rule suggestions
export { fetchRuleSuggestion, fetchMultipleSuggestions } from './rule-suggestion';

// Feature fetchers
export { fetchBotOverview } from './bot-defense-fetcher';
export { analyzeCDNCache } from './cdn-monitor';
export { fetchInfraProtectSummary } from './infraprotect-fetcher';
export { fetchCSDSummary } from './csd-fetcher';
export { fetchSyntheticHealth } from './synthetic-fetcher';
export { fetchDNSHealth } from './dns-monitor';
export { fetchAPISecuritySummary } from './api-security-monitor';

// Polling engine
export { PollingEngine } from './polling-engine';
