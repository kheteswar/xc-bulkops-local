import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, ChevronLeft, ChevronRight, type LucideIcon } from 'lucide-react';

export interface SlideDefinition {
  title: string;
  component: React.ComponentType;
}

interface SlideshowProps {
  slides: SlideDefinition[];
  /** Tool name shown in the header */
  toolName: string;
  /** Route to navigate to when clicking the CTA button */
  toolRoute: string;
  /** Icon for the CTA button */
  toolIcon: LucideIcon;
}

/**
 * Reusable slideshow shell for tool explainer pages.
 * Provides: prev/next buttons, dot indicators, keyboard navigation (← → Space),
 * slide counter, back button, and a persistent CTA to the tool.
 */
export function Slideshow({ slides, toolName, toolRoute, toolIcon: ToolIcon }: SlideshowProps) {
  const navigate = useNavigate();
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === ' ') { e.preventDefault(); setCurrent(s => Math.min(s + 1, slides.length - 1)); }
      if (e.key === 'ArrowLeft') { e.preventDefault(); setCurrent(s => Math.max(s - 1, 0)); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [slides.length]);

  const Slide = slides[current].component;

  return (
    <main className="max-w-5xl mx-auto px-6 py-6 min-h-screen flex flex-col">
      {/* Top nav */}
      <div className="flex items-center justify-between mb-6">
        <button onClick={() => navigate(-1)} className="flex items-center gap-1 text-sm text-slate-400 hover:text-slate-200">
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        <div className="flex items-center gap-1">
          {slides.map((_, i) => (
            <button key={i} onClick={() => setCurrent(i)}
              className={`h-2.5 rounded-full transition-all ${i === current ? 'bg-blue-500 w-6' : 'bg-slate-600 hover:bg-slate-500 w-2.5'}`}
              title={slides[i].title} />
          ))}
        </div>
        <div className="text-xs text-slate-500">{current + 1} / {slides.length}</div>
      </div>

      {/* Slide content */}
      <div className="flex-1 bg-slate-800/30 border border-slate-700 rounded-2xl p-8 min-h-[500px]">
        <Slide />
      </div>

      {/* Bottom nav */}
      <div className="flex items-center justify-between mt-6 pb-4">
        <button onClick={() => setCurrent(s => Math.max(s - 1, 0))} disabled={current === 0}
          className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 border border-slate-700 hover:border-slate-500 disabled:opacity-30 text-slate-200 rounded-lg text-sm transition-colors">
          <ChevronLeft className="w-4 h-4" /> Previous
        </button>
        <button onClick={() => navigate(toolRoute)}
          className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
          <ToolIcon className="w-4 h-4" /> Go to {toolName} <ChevronRight className="w-4 h-4" />
        </button>
        <button onClick={() => setCurrent(s => Math.min(s + 1, slides.length - 1))} disabled={current === slides.length - 1}
          className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 border border-slate-700 hover:border-slate-500 disabled:opacity-30 text-slate-200 rounded-lg text-sm transition-colors">
          Next <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </main>
  );
}

/** Intro slide — always the first slide of every tool explainer */
export function IntroSlide({ icon: Icon, toolName, tagline, what, problem, who, when }: {
  icon: LucideIcon;
  toolName: string;
  tagline: string;
  what: string;
  problem: string;
  who: string;
  when: string;
}) {
  return (
    <div className="flex flex-col items-center text-center">
      <div className="w-20 h-20 bg-blue-500/15 rounded-2xl flex items-center justify-center mb-6">
        <Icon className="w-10 h-10 text-blue-400" />
      </div>
      <h1 className="text-3xl font-bold text-slate-100 mb-2">{toolName}</h1>
      <p className="text-lg text-slate-400 mb-8 max-w-2xl">{tagline}</p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 w-full max-w-3xl text-left">
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-5">
          <div className="text-xs text-blue-400 font-semibold uppercase tracking-wider mb-2">What is it?</div>
          <p className="text-sm text-slate-300 leading-relaxed">{what}</p>
        </div>
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5">
          <div className="text-xs text-red-400 font-semibold uppercase tracking-wider mb-2">What problem does it solve?</div>
          <p className="text-sm text-slate-300 leading-relaxed">{problem}</p>
        </div>
        <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
          <div className="text-xs text-emerald-400 font-semibold uppercase tracking-wider mb-2">Who should use it?</div>
          <p className="text-sm text-slate-300 leading-relaxed">{who}</p>
        </div>
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-5">
          <div className="text-xs text-amber-400 font-semibold uppercase tracking-wider mb-2">When to use it?</div>
          <p className="text-sm text-slate-300 leading-relaxed">{when}</p>
        </div>
      </div>
    </div>
  );
}

/** Reusable slide title with icon */
export function SlideTitle({ icon: Icon, title, subtitle }: { icon: LucideIcon; title: string; subtitle: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="w-12 h-12 bg-blue-500/15 rounded-xl flex items-center justify-center"><Icon className="w-6 h-6 text-blue-400" /></div>
      <div><h2 className="text-2xl font-bold text-slate-100">{title}</h2><p className="text-sm text-slate-400">{subtitle}</p></div>
    </div>
  );
}

/** Feature card for intro slides */
export function FeatureCard({ icon: Icon, title, description, color = 'blue' }: {
  icon: LucideIcon; title: string; description: string; color?: string;
}) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
    emerald: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    amber: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    red: 'bg-red-500/10 border-red-500/30 text-red-400',
    violet: 'bg-violet-500/10 border-violet-500/30 text-violet-400',
    cyan: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
  };
  const c = colors[color] || colors.blue;
  const [bg, border, text] = c.split(' ');

  return (
    <div className={`${bg} border ${border} rounded-xl p-5`}>
      <div className="flex items-center gap-2 mb-2"><Icon className={`w-5 h-5 ${text}`} /><h3 className={`font-semibold ${text}`}>{title}</h3></div>
      <p className="text-sm text-slate-400">{description}</p>
    </div>
  );
}

/** Step list for pipeline/workflow slides */
export function StepList({ steps }: { steps: Array<{ icon: LucideIcon; title: string; desc: string; color: string }> }) {
  return (
    <div className="space-y-4">
      {steps.map((step, i) => (
        <div key={i} className="flex items-start gap-4">
          <div className="flex flex-col items-center">
            <div className={`w-10 h-10 rounded-full ${step.color} flex items-center justify-center text-white shadow-lg`}>
              <step.icon className="w-5 h-5" />
            </div>
            {i < steps.length - 1 && <div className="w-0.5 h-6 bg-slate-700" />}
          </div>
          <div className="flex-1 bg-slate-800/50 border border-slate-700 rounded-lg p-4">
            <h4 className="font-semibold text-slate-100">{step.title}</h4>
            <p className="text-sm text-slate-400 mt-1">{step.desc}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
