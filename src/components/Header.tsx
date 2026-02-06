import { Link, useLocation } from 'react-router-dom';
import { Plus, ExternalLink } from 'lucide-react';

export function Header() {
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Tools', hash: '#tools' },
    { to: '/', label: 'Backup Vault', hash: '#backup-vault' },
    { to: '/', label: 'Settings', hash: '#settings' },
  ];

  return (
    <header className="sticky top-0 z-50 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 h-16">
      <div className="max-w-7xl mx-auto px-6 h-full flex items-center justify-between">
        <Link to="/" className="flex items-center gap-3">
          <div className="w-10 h-10 text-blue-500">
            <svg viewBox="0 0 40 40" className="w-full h-full">
              <rect
                x="2"
                y="2"
                width="36"
                height="36"
                rx="8"
                stroke="currentColor"
                strokeWidth="2.5"
                fill="none"
              />
              <path
                d="M12 20h16M20 12v16"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
              />
            </svg>
          </div>
          <div className="flex flex-col">
            <span className="text-lg font-bold text-slate-100 tracking-tight">
              XC BulkOps
            </span>
            <span className="text-xs text-slate-500 font-medium">
              F5 XC Bulk Operations Toolbox
            </span>
          </div>
        </Link>

        <nav className="flex items-center gap-1">
          {navLinks.map(link => (
            <Link
              key={link.label}
              to={link.to + (link.hash || '')}
              className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors"
            >
              {link.label}
            </Link>
          ))}
          <a
            href="https://docs.cloud.f5.com/docs-v2/api"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-md transition-colors"
          >
            API Docs
            <ExternalLink className="w-3 h-3 opacity-50" />
          </a>
        </nav>
      </div>
    </header>
  );
}
