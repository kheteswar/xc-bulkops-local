import { ChevronRight, type LucideIcon } from 'lucide-react';
import { Link } from 'react-router-dom';

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
}: ToolCardProps) {
  const iconType = tags[0]?.type || 'report';
  const iconBg = iconBgStyles[iconType as keyof typeof iconBgStyles] || iconBgStyles.report;

  const content = (
    <article
      className={`relative flex flex-col p-6 rounded-xl border transition-all cursor-pointer group ${
        featured
          ? 'bg-gradient-to-b from-blue-500/10 to-slate-800/50 border-blue-500/30 hover:border-blue-500/50'
          : 'bg-slate-800/50 border-slate-700 hover:border-slate-600 hover:bg-slate-800/80'
      } ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/20'}`}
    >
      {featured && (
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500 to-cyan-500" />
      )}

      {badge && (
        <span className="absolute top-4 right-4 px-2 py-0.5 bg-blue-500 text-white text-[10px] font-bold uppercase tracking-wide rounded">
          {badge}
        </span>
      )}

      <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-4 ${iconBg}`}>
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
