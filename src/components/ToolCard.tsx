import { ChevronRight, HelpCircle, Pin, type LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';

/** Map tool routes to their explainer page routes */
const EXPLAINER_ROUTES: Record<string, string> = {
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

interface ToolCardProps {
  name: string;
  description: string;
  icon: LucideIcon;
  to?: string;
  onClick?: () => void;
  tags: Array<{ label: string; type: 'create' | 'update' | 'report' | 'safe' }>;
  badge?: string;
  featured?: boolean;
  disabled?: boolean;
  isPinned?: boolean;
  onTogglePin?: () => void;
}

const tagStyles = {
  create: 'bg-emerald-500/15 text-emerald-400',
  update: 'bg-amber-500/15 text-amber-400',
  report: 'bg-violet-500/15 text-violet-400',
  safe: 'bg-cyan-500/15 text-cyan-400',
};

const iconBgStyles = {
  create: 'bg-emerald-500/15 text-emerald-400',
  update: 'bg-amber-500/15 text-amber-400',
  report: 'bg-violet-500/15 text-violet-400',
};

export function ToolCard({
  name,
  description,
  icon: Icon,
  to,
  onClick,
  tags,
  badge,
  featured,
  disabled,
  isPinned,
  onTogglePin,
}: ToolCardProps) {
  const iconType = tags[0]?.type || 'report';
  const iconBg = iconBgStyles[iconType as keyof typeof iconBgStyles] || iconBgStyles.report;

  const pinButton = !disabled && onTogglePin ? (
    <button
      onClick={e => { e.preventDefault(); e.stopPropagation(); onTogglePin(); }}
      title={isPinned ? 'Unpin' : 'Pin to top'}
      className={`absolute top-3 left-3 z-10 p-1.5 rounded-md transition-all ${
        isPinned
          ? 'text-amber-400 bg-amber-400/15 hover:bg-amber-400/25'
          : 'text-slate-600 hover:text-slate-300 hover:bg-slate-700/60 opacity-0 group-hover:opacity-100'
      }`}
    >
      <Pin className={`w-3.5 h-3.5 ${isPinned ? 'fill-amber-400' : ''}`} />
    </button>
  ) : null;

  const content = (
    <article
      className={`relative flex flex-col p-6 rounded-xl border transition-all cursor-pointer group ${
        isPinned
          ? 'bg-gradient-to-b from-amber-500/10 to-slate-800/60 border-amber-500/40 hover:border-amber-500/60'
          : featured
          ? 'bg-gradient-to-b from-blue-500/10 to-slate-800/50 border-blue-500/30 hover:border-blue-500/50'
          : 'bg-slate-800/50 border-slate-700 hover:border-slate-600 hover:bg-slate-800/80'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/20'}`}
    >
      {pinButton}

      {isPinned && (
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-amber-500 to-yellow-400" />
      )}
      {!isPinned && featured && (
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500 to-cyan-500" />
      )}

      {badge && (
        <span className="absolute top-4 right-4 px-2 py-0.5 bg-blue-500 text-white text-[10px] font-bold uppercase tracking-wide rounded">
          {badge}
        </span>
      )}

      {to && EXPLAINER_ROUTES[to] && (
        <Link
          to={EXPLAINER_ROUTES[to]}
          onClick={e => e.stopPropagation()}
          className="absolute bottom-4 right-14 z-10 flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 border border-transparent hover:border-blue-500/30 transition-all"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          <span>How it works</span>
        </Link>
      )}

      <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-4 ${isPinned ? 'bg-amber-500/15 text-amber-400' : iconBg}`}>
        <Icon className="w-6 h-6" />
      </div>

      <div className="flex-1 mb-4">
        <h3 className="text-lg font-semibold text-slate-100 mb-2">{name}</h3>
        <p className="text-sm text-slate-400 leading-relaxed">{description}</p>
      </div>

      <div className="flex items-center gap-2 mb-2">
        {tags.map((tag, i) => (
          <span
            key={i}
            className={`px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide rounded ${tagStyles[tag.type]}`}
          >
            {tag.label}
          </span>
        ))}
      </div>

      <div className="absolute bottom-6 right-6 text-slate-500 group-hover:text-blue-400 group-hover:translate-x-1 transition-all">
        <ChevronRight className="w-5 h-5" />
      </div>
    </article>
  );

  if (disabled) {
    return content;
  }

  if (to) {
    return <Link to={to}>{content}</Link>;
  }

  return (
    <div onClick={onClick} role="button" tabIndex={0}>
      {content}
    </div>
  );
}
