import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { ToastProvider } from './context/ToastContext';
import { Header } from './components/Header';
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

function App() {
  return (
    <BrowserRouter>
      <AppProvider>
        <ToastProvider>
          <div className="min-h-screen bg-slate-900">
            <Routes>
              <Route
                path="/"
                element={
                  <>
                    <Header />
                    <Home />
                  </>
                }
              />
              <Route path="/waf-scanner" element={<WAFScanner />} />
              <Route path="/config-visualizer" element={<ConfigVisualizer />} />
              <Route path="/copy-config" element={<CopyConfig />} />
              <Route path="/security-auditor" element={<SecurityAuditor />} />
              <Route path="/property-viewer" element={<PropertyViewer />} />
              <Route path="/config-comparator" element={<ConfigComparator />} />
              <Route path="/http-sanity-checker" element={<HttpSanityChecker />} />
              <Route path="/prefix-builder" element={<PrefixBuilder />} />
              <Route path="/http-lb-forge" element={<HttpLbForge />} />
            </Routes>
          </div>
        </ToastProvider>
      </AppProvider>
    </BrowserRouter>
  );
}

export default App;