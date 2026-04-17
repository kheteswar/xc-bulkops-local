import { HelpCircle, type LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';

/** Map tool routes to explainer routes */
const EXPLAINER_MAP: Record<string, string> = {
  '/waf-scanner': '/explainer/waf-scanner',
  '/security-auditor': '/explainer/security-auditor',
  '/fp-analyzer': '/explainer/fp-analyzer',
  '/ddos-advisor': '/explainer/ddos-advisor',
  '/config-visualizer': '/explainer/config-viewer',
  '/config-comparator': '/explainer/config-comparator',
  '/config-explorer': '/explainer/dependency-map',
  '/config-dump': '/explainer/config-dump',
  '/http-sanity-checker': '/explainer/http-sanity',
  '/log-analyzer': '/explainer/log-analyzer',
  '/load-tester': '/explainer/load-tester',
  '/api-shield': '/explainer/api-shield',
  '/api-report': '/explainer/api-report',
  '/soc-lobby': '/explainer/soc-room',
  '/prefix-builder': '/explainer/prefix-builder',
  '/copy-config': '/explainer/copy-config',
  '/property-viewer': '/explainer/property-viewer',
  '/http-lb-forge': '/explainer/http-lb-forge',
  '/rate-limit-advisor': '/rate-limit-explainer',
};

/**
 * Shared header for tool pages. Shows tool name, description,
 * and a "How does this work?" link to the explainer slideshow.
 *
 * Usage:
 *   <ToolPageHeader icon={Shield} title="WAF Scanner" description="..." route="/waf-scanner" />
 */
export function ToolPageHeader({ icon: Icon, title, description, route }: {
  icon: LucideIcon;
  title: string;
  description: string;
  route: string;
}) {
  const explainerRoute = EXPLAINER_MAP[route];

  return (
    <div className="mb-8 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-blue-500/15 rounded-xl flex items-center justify-center">
          <Icon className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">{title}</h1>
          <p className="text-sm text-slate-400">{description}</p>
        </div>
      </div>
      {explainerRoute && (
        <Link to={explainerRoute}
          className="flex items-center gap-1.5 px-4 py-2 bg-slate-800 border border-slate-700 hover:border-blue-500/50 text-slate-300 hover:text-blue-400 rounded-lg text-sm transition-colors">
          <HelpCircle className="w-4 h-4" /> How does this work?
        </Link>
      )}
    </div>
  );
}
