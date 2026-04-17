import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export type Theme = 'dark' | 'light' | 'warm';

const ThemeContext = createContext<{ theme: Theme; cycleTheme: () => void }>({
  theme: 'dark',
  cycleTheme: () => {},
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem('xc-theme') as Theme) || 'dark'
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('xc-theme', theme);
  }, [theme]);

  const cycleTheme = () =>
    setTheme(t => (t === 'dark' ? 'light' : t === 'light' ? 'warm' : 'dark'));

  return (
    <ThemeContext.Provider value={{ theme, cycleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
