import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { ToastProvider } from './context/ToastContext';
import { Header } from './components/Header';
import Footer from './components/Footer';
import { Home } from './pages/Home';
import { WAFScanner } from './pages/WAFScanner';
import { ConfigVisualizer } from './pages/ConfigVisualizer';
import { CopyConfig } from './pages/CopyConfig';
import { SecurityAuditor } from './pages/SecurityAuditor';
import { PropertyViewer } from './pages/PropertyViewer';
import { ConfigComparator } from './pages/ConfigComparator';
import { HttpSanityChecker } from './pages/HttpSanityChecker';
import { PrefixBuilder } from './pages/PrefixBuilder';
import { HttpLbForge } from './pages/HttpLbForge';
import { TimeTracker } from './pages/TimeTracker';
import { RateLimitAdvisor } from './pages/RateLimitAdvisor';
import FPAnalyzer from './pages/FPAnalyzer';
import { ConfigDump } from './pages/ConfigDump';
import { ConfigExplorer } from './pages/ConfigExplorer';
import { DdosAdvisor } from './pages/DdosAdvisor';
import { LogAnalyzer } from './pages/LogAnalyzer';

function App() {
  return (
    <BrowserRouter>
      <AppProvider>
        <ToastProvider>
          <div className="min-h-screen bg-slate-900">
            <Header />
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/waf-scanner" element={<WAFScanner />} />
              <Route path="/config-visualizer" element={<ConfigVisualizer />} />
              <Route path="/copy-config" element={<CopyConfig />} />
              <Route path="/security-auditor" element={<SecurityAuditor />} />
              <Route path="/property-viewer" element={<PropertyViewer />} />
              <Route path="/config-comparator" element={<ConfigComparator />} />
              <Route path="/http-sanity-checker" element={<HttpSanityChecker />} />
              <Route path="/prefix-builder" element={<PrefixBuilder />} />
              <Route path="/http-lb-forge" element={<HttpLbForge />} />
              <Route path="/time-tracker" element={<TimeTracker />} />
              <Route path="/rate-limit-advisor" element={<RateLimitAdvisor />} />
              <Route path="/fp-analyzer" element={<FPAnalyzer />} />
              <Route path="/config-dump" element={<ConfigDump />} />
              <Route path="/config-explorer" element={<ConfigExplorer />} />
              <Route path="/ddos-advisor" element={<DdosAdvisor />} />
              <Route path="/log-analyzer" element={<LogAnalyzer />} />
            </Routes>
            <Footer />
          </div>
        </ToastProvider>
      </AppProvider>
    </BrowserRouter>
  );
}

export default App;