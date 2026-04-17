import React, { useState } from 'react';
import {
  Search,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  AlertTriangle,
  Shield,
  FileText,
  GitBranch,
} from 'lucide-react';
import type { Investigation, InvestigationStep, RemediationAction } from '../../services/live-soc/types';

interface InvestigationPanelProps {
  active: Investigation[];
  completed: Investigation[];
  onCrossLaunch?: (tool: string, context: Record<string, unknown>) => void;
}

function severityColor(severity: string): string {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'text-[#ff0040] bg-[#ff0040]/10 border-[#ff0040]/30';
  if (s === 'HIGH') return 'text-[#ff6b35] bg-[#ff6b35]/10 border-[#ff6b35]/30';
  if (s === 'MEDIUM') return 'text-[#ffbe0b] bg-[#ffbe0b]/10 border-[#ffbe0b]/30';
  return 'text-[#00d4ff] bg-[#00d4ff]/10 border-[#00d4ff]/30';
}

function statusIcon(status: string): React.ReactNode {
  switch (status) {
    case 'running':
      return <Loader2 className="w-4 h-4 text-[#00d4ff] animate-spin" />;
    case 'complete':
      return <CheckCircle2 className="w-4 h-4 text-[#00ff88]" />;
    case 'error':
      return <XCircle className="w-4 h-4 text-[#ff0040]" />;
    case 'pending':
      return <Clock className="w-4 h-4 text-gray-500" />;
    default:
      return <Clock className="w-4 h-4 text-gray-500" />;
  }
}

function stepStatusIcon(status: string): React.ReactNode {
  switch (status) {
    case 'running':
      return <Loader2 className="w-3 h-3 text-[#00d4ff] animate-spin" />;
    case 'complete':
      return <CheckCircle2 className="w-3 h-3 text-[#00ff88]" />;
    case 'error':
      return <XCircle className="w-3 h-3 text-[#ff0040]" />;
    case 'skipped':
      return <span className="w-3 h-3 text-gray-600 text-center text-[10px]">—</span>;
    case 'pending':
    default:
      return <span className="w-3 h-3 rounded-full border border-gray-600 inline-block" />;
  }
}

function formatWorkflowName(id: string): string {
  return id
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function StepRow({ step, expanded, onToggle }: { step: InvestigationStep; expanded: boolean; onToggle: () => void }) {
  const hasEvidence = step.evidence && Object.keys(step.evidence).length > 0;

  return (
    <div className="ml-4">
      <button
        onClick={hasEvidence ? onToggle : undefined}
        className={`flex items-center gap-2 py-1 w-full text-left ${
          hasEvidence ? 'cursor-pointer hover:bg-[#1a2332]/30' : 'cursor-default'
        } rounded px-1 transition-colors`}
      >
        {stepStatusIcon(step.status)}
        <span
          className={`text-[11px] ${
            step.status === 'complete'
              ? 'text-gray-300'
              : step.status === 'running'
                ? 'text-[#00d4ff]'
                : step.status === 'error'
                  ? 'text-[#ff0040]'
                  : 'text-gray-500'
          }`}
        >
          {step.label}
        </span>
        {hasEvidence && (
          <span className="ml-auto">
            {expanded ? (
              <ChevronDown className="w-3 h-3 text-gray-500" />
            ) : (
              <ChevronRight className="w-3 h-3 text-gray-500" />
            )}
          </span>
        )}
        {step.error && (
          <span className="ml-2 text-[10px] text-[#ff0040] truncate max-w-[150px]">
            {step.error}
          </span>
        )}
      </button>

      {expanded && step.evidence && (
        <div className="ml-5 mt-1 mb-2 bg-[#0a0e1a]/60 rounded-lg p-2 border border-[#1a2332]">
          {Object.entries(step.evidence).map(([key, value]) => (
            <div key={key} className="flex gap-2 py-0.5">
              <span className="text-[10px] text-gray-500 font-mono w-24 flex-shrink-0 truncate">
                {key}:
              </span>
              <span className="text-[10px] text-gray-300 font-mono break-all">
                {typeof value === 'object' ? JSON.stringify(value, null, 0) : String(value)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RemediationButton({
  action,
  onCrossLaunch,
}: {
  action: RemediationAction;
  onCrossLaunch?: (tool: string, context: Record<string, unknown>) => void;
}) {
  const isCrossLaunch = action.type === 'cross_launch' && action.targetTool;

  return (
    <button
      onClick={() => {
        if (isCrossLaunch && onCrossLaunch && action.targetTool) {
          onCrossLaunch(action.targetTool, action.context || {});
        }
      }}
      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors ${
        isCrossLaunch
          ? 'bg-[#00d4ff]/10 text-[#00d4ff] border border-[#00d4ff]/30 hover:bg-[#00d4ff]/20'
          : action.type === 'rule_suggestion'
            ? 'bg-[#ffbe0b]/10 text-[#ffbe0b] border border-[#ffbe0b]/30 hover:bg-[#ffbe0b]/20'
            : 'bg-[#1a2332] text-gray-400 border border-[#1a2332] hover:bg-[#1a2332]/80'
      }`}
    >
      {isCrossLaunch ? (
        <ExternalLink className="w-3 h-3" />
      ) : action.type === 'rule_suggestion' ? (
        <Shield className="w-3 h-3" />
      ) : (
        <FileText className="w-3 h-3" />
      )}
      {action.label}
    </button>
  );
}

function InvestigationNode({
  investigation,
  allInvestigations,
  onCrossLaunch,
  depth = 0,
}: {
  investigation: Investigation;
  allInvestigations: Investigation[];
  onCrossLaunch?: (tool: string, context: Record<string, unknown>) => void;
  depth?: number;
}) {
  const [expanded, setExpanded] = useState(investigation.status === 'running');
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  const toggleStep = (stepId: string) => {
    setExpandedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(stepId)) next.delete(stepId);
      else next.add(stepId);
      return next;
    });
  };

  const completedSteps = investigation.steps.filter((s) => s.status === 'complete').length;
  const totalSteps = investigation.steps.length;

  const childInvestigations = allInvestigations.filter(
    (inv) => investigation.childInvestigationIds.includes(inv.id)
  );

  return (
    <div className={`${depth > 0 ? 'ml-4 border-l-2 border-[#1a2332] pl-3' : ''}`}>
      {/* Investigation header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 w-full text-left py-2 px-2 rounded-lg hover:bg-[#1a2332]/30 transition-colors"
      >
        {statusIcon(investigation.status)}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-200 truncate">
              {formatWorkflowName(investigation.workflowId)}
            </span>
            {investigation.finding && (
              <span
                className={`text-[9px] font-semibold uppercase px-1.5 py-0.5 rounded border ${severityColor(
                  investigation.finding.severity
                )}`}
              >
                {investigation.finding.severity}
              </span>
            )}
            {childInvestigations.length > 0 && (
              <span className="flex items-center gap-0.5 text-[10px] text-gray-500">
                <GitBranch className="w-3 h-3" />
                {childInvestigations.length}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-gray-500">
              {formatTimestamp(investigation.createdAt)}
            </span>
            <span className="text-[10px] text-gray-600">
              {completedSteps}/{totalSteps} steps
            </span>
          </div>
        </div>
        {/* Progress bar */}
        <div className="w-16 h-1.5 bg-[#1a2332] rounded-full overflow-hidden flex-shrink-0">
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${totalSteps > 0 ? (completedSteps / totalSteps) * 100 : 0}%`,
              backgroundColor:
                investigation.status === 'error'
                  ? '#ff0040'
                  : investigation.status === 'complete'
                    ? '#00ff88'
                    : '#00d4ff',
            }}
          />
        </div>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
        )}
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="mt-1 mb-2">
          {/* Steps */}
          <div className="space-y-0">
            {investigation.steps.map((step) => (
              <StepRow
                key={step.id}
                step={step}
                expanded={expandedSteps.has(step.id)}
                onToggle={() => toggleStep(step.id)}
              />
            ))}
          </div>

          {/* Finding */}
          {investigation.finding && (
            <div className="ml-4 mt-2 bg-[#0a0e1a]/60 rounded-lg p-3 border border-[#1a2332]">
              <div className="flex items-center gap-1.5 mb-1">
                <AlertTriangle
                  className="w-3.5 h-3.5"
                  style={{
                    color:
                      investigation.finding.severity === 'CRITICAL'
                        ? '#ff0040'
                        : investigation.finding.severity === 'HIGH'
                          ? '#ff6b35'
                          : '#ffbe0b',
                  }}
                />
                <span className="text-xs font-semibold text-gray-200">
                  {investigation.finding.rootCause}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 mb-2">
                {investigation.finding.evidenceSummary}
              </p>

              {/* Remediation Actions */}
              {investigation.finding.remediationActions.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {investigation.finding.remediationActions.map((action, i) => (
                    <RemediationButton
                      key={i}
                      action={action}
                      onCrossLaunch={onCrossLaunch}
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Child investigations */}
          {childInvestigations.length > 0 && (
            <div className="mt-2">
              {childInvestigations.map((child) => (
                <InvestigationNode
                  key={child.id}
                  investigation={child}
                  allInvestigations={allInvestigations}
                  onCrossLaunch={onCrossLaunch}
                  depth={depth + 1}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function InvestigationPanel({
  active,
  completed,
  onCrossLaunch,
}: InvestigationPanelProps) {
  const [showCompleted, setShowCompleted] = useState(false);

  const allInvestigations = [...active, ...completed];

  // Filter to root investigations (no parent)
  const rootActive = active.filter((inv) => !inv.parentInvestigationId);
  const rootCompleted = completed.filter((inv) => !inv.parentInvestigationId);

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Search className="w-4 h-4 text-[#00d4ff]" />
          <h3 className="text-sm font-semibold text-gray-200">Investigations</h3>
        </div>
        <div className="flex items-center gap-2">
          {active.length > 0 && (
            <span className="text-[10px] text-[#00d4ff] bg-[#00d4ff]/10 px-1.5 py-0.5 rounded font-medium">
              {active.length} active
            </span>
          )}
          {completed.length > 0 && (
            <span className="text-[10px] text-gray-500 bg-[#1a2332] px-1.5 py-0.5 rounded font-medium">
              {completed.length} completed
            </span>
          )}
        </div>
      </div>

      {/* Active Investigations */}
      {rootActive.length === 0 && rootCompleted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 text-gray-500">
          <Search className="w-8 h-8 mb-2 opacity-30" />
          <p className="text-xs">No investigations running</p>
          <p className="text-[10px] text-gray-600 mt-0.5">
            Investigations trigger automatically when anomalies are detected
          </p>
        </div>
      ) : (
        <>
          {/* Active */}
          {rootActive.length > 0 && (
            <div className="space-y-1 mb-3">
              {rootActive.map((inv) => (
                <InvestigationNode
                  key={inv.id}
                  investigation={inv}
                  allInvestigations={allInvestigations}
                  onCrossLaunch={onCrossLaunch}
                />
              ))}
            </div>
          )}

          {/* Completed (collapsible) */}
          {rootCompleted.length > 0 && (
            <div className="border-t border-[#1a2332] pt-3">
              <button
                onClick={() => setShowCompleted(!showCompleted)}
                className="flex items-center gap-2 w-full text-left py-1 px-1 rounded hover:bg-[#1a2332]/30 transition-colors"
              >
                {showCompleted ? (
                  <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
                )}
                <span className="text-xs text-gray-400">
                  Completed ({rootCompleted.length})
                </span>
              </button>

              {showCompleted && (
                <div className="mt-1 space-y-1 opacity-70">
                  {rootCompleted.map((inv) => (
                    <InvestigationNode
                      key={inv.id}
                      investigation={inv}
                      allInvestigations={allInvestigations}
                      onCrossLaunch={onCrossLaunch}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
