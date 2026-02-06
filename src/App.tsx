import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { ToastProvider } from './context/ToastContext';
import { Header } from './components/Header';
import { Home } from './pages/Home';
import { WAFScanner } from './pages/WAFScanner';
import { ConfigVisualizer } from './pages/ConfigVisualizer';
import { CopyConfig } from './pages/CopyConfig';

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
            </Routes>
          </div>
        </ToastProvider>
      </AppProvider>
    </BrowserRouter>
  );
}

export default App;
