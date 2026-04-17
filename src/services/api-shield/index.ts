// ═══════════════════════════════════════════════════════════════════
// API Shield Advisor — Barrel Exports
// ═══════════════════════════════════════════════════════════════════

// Types
export type {
  AssessmentDepth,
  AssessmentConfig,
  LBSecurityConfig,
  ControlPhase,
  ControlPriority,
  ControlStatusValue,
  SecurityControl,
  ControlStatus,
  DiscoveredEndpoint,
  APIDiscoveryInsight,
  TrafficProfileInsight,
  SecuritySummaryInsight,
  Recommendation,
  PhaseProgress,
  OWASPCoverage,
  DomainScore,
  AssessmentResult,
} from './types';

// Control catalog
export {
  CONTROL_DOMAINS,
  OWASP_API_TOP_10,
  IMPLEMENTATION_PHASES,
  getControlById,
  getControlsByDomain,
  getControlsByPhase,
  getAllControls,
  getTotalControlCount,
  getControlsForOWASP,
  buildOWASPCoverage,
  buildPhaseProgress,
  getPhaseOrder,
  getDomainForControl,
} from './control-catalog';

export type { ControlDomainId, ControlDomainMeta } from './control-catalog';

// Security assessor (orchestrator)
export { runAssessment } from './security-assessor';
