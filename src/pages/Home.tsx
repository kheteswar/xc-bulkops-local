import {
  Wrench,
  Globe,
  Grid3X3,
  RefreshCcw,
  Shield,
  User,
  AlertTriangle,
  Search,
  Download,
  FileText,
  Save,
  Layout,
  Clock,
  Eye,
  Activity,
  Lock,
  ChevronRight,
  Copy,
} from 'lucide-react';
import { ConnectionPanel } from '../components/ConnectionPanel';
import { ToolCard } from '../components/ToolCard';
import { useApp } from '../context/AppContext';

const tools = [
  {
    name: 'Config Visualizer',
    description: 'Interactive map of Load Balancer dependencies and configuration settings.',
    icon: Grid3X3,
    to: '/config-visualizer',
    tags: [
      { label: 'Visualize', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'WAF Status Scanner',
    description: 'Audit WAF modes, exclusion rules, and security status across all load balancers.',
    icon: Search,
    to: '/waf-scanner',
    tags: [
      { label: 'Report', type: 'report' as const },
      { label: 'Read-Only', type: 'safe' as const },
    ],
    badge: 'Start Here',
    featured: true,
  },
  {
    name: 'Copy Config',
    description: 'Copy configuration objects across tenants or namespaces. Supports Alert Receivers and Policies.',
    icon: Copy,
    to: '/copy-config',
    tags: [
      { label: 'Create', type: 'create' as const },
      { label: 'Cross-Tenant', type: 'update' as const },
    ],
    badge: 'New',
    featured: true,
  },
  {
    name: 'LB Forge',
    description: 'Create multiple HTTP Load Balancers at scale from CSV input.',
    icon: Wrench,
    tags: [{ label: 'Create', type: 'create' as const }],
    disabled: true,
  },
  {
    name: 'CDN Factory',
    description: 'Spin up CDN distributions en masse with bulk configuration.',
    icon: Globe,
    tags: [{ label: 'Create', type: 'create' as const }],
    disabled: true,
  },
  {
    name: 'Prefix Builder',
    description: 'Build IP prefix sets in bulk for firewall and routing rules.',
    icon: Grid3X3,
    tags: [{ label: 'Create', type: 'create' as const }],
    disabled: true,
  },
  {
    name: 'Config Sync',
    description: 'Mass update settings across HTTP Load Balancers (HSTS, API Discovery, etc.)',
    icon: RefreshCcw,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Policy Pusher',
    description: 'Deploy service policies fleet-wide across load balancers.',
    icon: Shield,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Identity Roller',
    description: 'Roll out user identification policies everywhere.',
    icon: User,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Threat Toggle',
    description: 'Enable/disable Malicious User Detection across all apps.',
    icon: AlertTriangle,
    tags: [{ label: 'Update', type: 'update' as const }],
    disabled: true,
  },
  {
    name: 'Log Harvester',
    description: 'Extract logs for a given duration for offline analysis.',
    icon: Download,
    tags: [{ label: 'Export', type: 'report' as const }],
    disabled: true,
  },
  {
    name: 'Security Auditor',
    description: 'Comprehensive security posture report across all configurations.',
    icon: FileText,
    tags: [{ label: 'Report', type: 'report' as const }],
    disabled: true,
  },
];

const features = [
  {
    icon: Save,
    title: 'Auto-Backup',
    description: 'Every operation creates a restore point. Roll back with one click if needed.',
  },
  {
    icon: Layout,
    title: 'Before/After Diff',
    description: 'See exactly what changed with side-by-side configuration comparison.',
  },
  {
    icon: Clock,
    title: 'Rate Limiting',
    description: "Smart queue with configurable rate limits. Never hit API throttling.",
  },
  {
    icon: Eye,
    title: 'Dry Run Preview',
    description: 'Preview all changes before execution. Nothing happens until you confirm.',
  },
  {
    icon: Activity,
    title: 'Live Progress',
    description: 'Real-time progress tracking with ETA. Pause and resume anytime.',
  },
  {
    icon: Lock,
    title: 'Secure Proxy',
    description: 'Server-side proxy ensures secure API communication. No CORS issues.',
  },
];

export function Home() {
  const { isConnected } = useApp();

  return (
    <main className="max-w-7xl mx-auto px-6 py-8">
      <ConnectionPanel />

      <section className="mb-8">
        <div className="flex items-center gap-4 p-4 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-slate-600 transition-colors cursor-pointer">
          <div className="w-12 h-12 bg-violet-500/15 rounded-xl flex items-center justify-center text-violet-400">
            <Save className="w-6 h-6" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-slate-100 mb-0.5">Backup Vault</h3>
            <p className="text-sm text-slate-400">
              <span className="font-semibold text-violet-400">0</span> restore points available
            </p>
          </div>
          <button className="flex items-center gap-1 px-4 py-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700 rounded-lg transition-colors text-sm font-medium">
            View All
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </section>

      <section id="tools" className="mb-12">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-slate-100 mb-2">Bulk Operations</h2>
          <p className="text-slate-400">
            Select a tool to perform bulk configuration operations on your F5 XC environment
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {tools.map(tool => (
            <ToolCard
              key={tool.name}
              {...tool}
              disabled={tool.disabled || !isConnected}
            />
          ))}
        </div>
      </section>

      <section className="mb-12">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-slate-100 mb-2">Built for Safety & Scale</h2>
          <p className="text-slate-400">Enterprise-grade features for production environments</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map(feature => (
            <div
              key={feature.title}
              className="p-6 bg-slate-800/50 border border-slate-700 rounded-xl hover:border-slate-600 transition-colors"
            >
              <div className="w-10 h-10 bg-slate-700 rounded-lg flex items-center justify-center text-blue-400 mb-4">
                <feature.icon className="w-5 h-5" />
              </div>
              <h3 className="font-semibold text-slate-100 mb-2">{feature.title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      <footer className="border-t border-slate-800 pt-6 pb-12">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">XC BulkOps</span>
            <span className="px-2 py-0.5 bg-slate-800 rounded text-xs text-slate-500 font-mono">
              v1.0.0
            </span>
          </div>
          <p className="text-sm text-slate-500">
            This tool is not affiliated with or endorsed by F5, Inc. Use at your own risk.
          </p>
          <div className="flex items-center gap-4 text-sm">
            <a
              href="https://docs.cloud.f5.com/docs-v2/api"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-slate-200 transition-colors"
            >
              F5 XC API Docs
            </a>
            <span className="text-slate-600">-</span>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-slate-200 transition-colors"
            >
              GitHub
            </a>
          </div>
        </div>
      </footer>
    </main>
  );
}
