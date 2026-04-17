import { Code2, Globe, CreditCard } from 'lucide-react';
import type { CSDSummary } from '../../services/live-soc/types';

interface CSDMonitorProps {
  data: CSDSummary | null;
}

function classificationColor(classification: string): string {
  switch (classification) {
    case 'malicious':
      return 'text-[#ff0040] bg-[#ff0040]/10 border-[#ff0040]/30';
    case 'suspicious':
      return 'text-[#ffbe0b] bg-[#ffbe0b]/10 border-[#ffbe0b]/30';
    case 'benign':
      return 'text-[#00ff88] bg-[#00ff88]/10 border-[#00ff88]/30';
    default:
      return 'text-gray-400 bg-gray-400/10 border-gray-400/30';
  }
}

export default function CSDMonitor({ data }: CSDMonitorProps) {
  if (!data) {
    return (
      <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
        <div className="flex items-center gap-2 mb-4">
          <Code2 className="w-4 h-4 text-[#a855f7]" />
          <h3 className="text-sm font-semibold text-gray-200">Client-Side Defense</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <Code2 className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm font-medium text-gray-400">CSD Not Enabled</p>
          <p className="text-xs text-gray-600 mt-1">
            Enable Client-Side Defense to monitor third-party scripts
          </p>
        </div>
      </div>
    );
  }

  const paymentTargeting = data.scripts.some((s) =>
    s.targetedFormFields.some(
      (f) =>
        f.toLowerCase().includes('card') ||
        f.toLowerCase().includes('cvv') ||
        f.toLowerCase().includes('payment') ||
        f.toLowerCase().includes('credit')
    )
  );

  const maliciousScripts = data.scripts.filter((s) => s.classification === 'malicious');
  const suspiciousScripts = data.scripts.filter((s) => s.classification === 'suspicious');
  const suspiciousDomains = data.detectedDomains.filter(
    (d) => d.classification === 'suspicious' || d.classification === 'malicious'
  );

  return (
    <div className="bg-[#0f1423]/70 backdrop-blur-xl border border-[#1a2332] rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-[#a855f7]" />
          <h3 className="text-sm font-semibold text-gray-200">Client-Side Defense</h3>
        </div>
        <span className="text-xs font-mono text-gray-500">
          {data.scripts.length} scripts tracked
        </span>
      </div>

      {/* Payment Field Targeting Alert */}
      {paymentTargeting && (
        <div className="mb-4 flex items-start gap-2 bg-[#ff0040]/10 border border-[#ff0040]/30 rounded-lg p-3 animate-pulse">
          <CreditCard className="w-4 h-4 text-[#ff0040] flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-xs font-bold text-[#ff0040] uppercase tracking-wider">
              Payment Field Targeting Detected
            </p>
            <p className="text-[11px] text-gray-400 mt-0.5">
              One or more scripts are targeting payment/credit card form fields. Potential Magecart attack.
            </p>
          </div>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="bg-[#0a0e1a]/50 rounded-lg p-2.5 text-center">
          <span className="block text-lg font-bold font-mono text-gray-200">
            {data.scripts.length}
          </span>
          <span className="text-[10px] text-gray-500 uppercase">Total Scripts</span>
        </div>
        <div className="bg-[#0a0e1a]/50 rounded-lg p-2.5 text-center">
          <span className="block text-lg font-bold font-mono text-[#ff0040]">
            {maliciousScripts.length}
          </span>
          <span className="text-[10px] text-gray-500 uppercase">Malicious</span>
        </div>
        <div className="bg-[#0a0e1a]/50 rounded-lg p-2.5 text-center">
          <span className="block text-lg font-bold font-mono text-[#ffbe0b]">
            {suspiciousScripts.length}
          </span>
          <span className="text-[10px] text-gray-500 uppercase">Suspicious</span>
        </div>
      </div>

      {/* Script Inventory Table */}
      <div className="mb-4">
        <h4 className="text-[11px] text-gray-500 uppercase tracking-wider mb-2">
          Script Inventory
        </h4>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[#1a2332]">
                <th className="text-left text-[10px] text-gray-500 uppercase tracking-wider py-1.5 pr-3">
                  Domain
                </th>
                <th className="text-left text-[10px] text-gray-500 uppercase tracking-wider py-1.5 pr-3">
                  Status
                </th>
                <th className="text-left text-[10px] text-gray-500 uppercase tracking-wider py-1.5 pr-3">
                  Targeted Fields
                </th>
                <th className="text-right text-[10px] text-gray-500 uppercase tracking-wider py-1.5">
                  Users
                </th>
              </tr>
            </thead>
            <tbody>
              {data.scripts.map((script) => (
                <tr
                  key={script.id}
                  className="border-b border-[#1a2332]/50 hover:bg-[#1a2332]/30 transition-colors"
                >
                  <td className="py-1.5 pr-3">
                    <span className="font-mono text-gray-300 truncate max-w-[200px] inline-block">
                      {script.domain}
                    </span>
                  </td>
                  <td className="py-1.5 pr-3">
                    <span
                      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${classificationColor(
                        script.classification
                      )}`}
                    >
                      {script.classification}
                    </span>
                  </td>
                  <td className="py-1.5 pr-3">
                    {script.targetedFormFields.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {script.targetedFormFields.map((field) => (
                          <span
                            key={field}
                            className="text-[10px] bg-[#1a2332] text-gray-400 px-1.5 py-0.5 rounded font-mono"
                          >
                            {field}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-gray-600">&mdash;</span>
                    )}
                  </td>
                  <td className="py-1.5 text-right font-mono text-gray-400">
                    {script.affectedUserCount.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Suspicious Domains */}
      {suspiciousDomains.length > 0 && (
        <div className="pt-3 border-t border-[#1a2332]">
          <div className="flex items-center gap-1.5 mb-2">
            <Globe className="w-3.5 h-3.5 text-[#ffbe0b]" />
            <h4 className="text-[11px] text-gray-500 uppercase tracking-wider">
              Suspicious Domains
            </h4>
          </div>
          <div className="space-y-1">
            {suspiciousDomains.map((d) => (
              <div
                key={d.domain}
                className="flex items-center justify-between py-1 px-1 rounded hover:bg-[#1a2332]/50 transition-colors"
              >
                <span className="text-xs font-mono text-gray-300">{d.domain}</span>
                <div className="flex items-center gap-2">
                  <span
                    className={`text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded border ${classificationColor(
                      d.classification
                    )}`}
                  >
                    {d.classification}
                  </span>
                  {d.mitigated && (
                    <span className="text-[10px] text-[#00ff88] bg-[#00ff88]/10 px-1.5 py-0.5 rounded">
                      Mitigated
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
