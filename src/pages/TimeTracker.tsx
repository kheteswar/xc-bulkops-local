import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { 
  Save, Download, Upload, Plus, Trash2, Send, Clock, 
  Settings, AlertCircle, ChevronLeft, ChevronRight, KeyRound, Loader2,
  ChevronDown, Search, Globe, RefreshCw, RotateCcw
} from 'lucide-react';
import { useToast } from '../context/ToastContext';

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS & TYPES
// ═══════════════════════════════════════════════════════════════════════════

const API_BASE_DOMAIN = 'time-tracker.mgdsvc-ai.f5sdclabs.com';

const DEFAULT_PRODUCTS = [
  'AI Guardrails / AI Red Team', 'BIG-IP', 'Bot Standard', 'Bot Web & Mobile', 
  'Not Apply', 'Other', 'Shape - Bot Defense (IBD)', 'XC API Security', 
  'XC CDN', 'XC Data Intelligence', 'XC DDoS', 'XC DNS', 'XC General', 
  'XC MCN', 'XC Mobile App Shield', 'XC WAF', 'XC Web App Scanning'
];

const DEFAULT_WORK_TYPES = [
  'Business as Usual', 'Customer Escalation', 'Customer Onboarding', 
  'Customer Training', 'Exception', 'F5 Wellness Day', 'Free of Charge', 
  'Holiday', 'Internal Meetings', 'Internal Training', 'On-call', 
  'Proof of Concept', 'PTO', 'Self-Development', 'XC Expert Hours'
];

const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;
type Day = typeof DAYS[number];

interface TimeRow {
  id: string;
  customerName: string;
  productName: string;
  workTypeName: string;
  hours: Record<Day, string>;
}

interface ReferenceItem {
  id: string;
  name: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

const generateId = () => {
  return typeof crypto !== 'undefined' && crypto.randomUUID 
    ? crypto.randomUUID() 
    : Math.random().toString(36).substring(2, 15);
};

const getStartOfWeek = (date: Date) => {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0); // Strictly reset to midnight to prevent timezone boundary bugs
  const day = d.getDay() || 7; 
  d.setDate(d.getDate() - (day - 1));
  return d;
};

const getDatesForWeekOffset = (offsetWeeks: number) => {
  const start = getStartOfWeek(new Date());
  start.setDate(start.getDate() + (offsetWeeks * 7));
  
  const dates: Record<string, { label: string, fullDate: string }> = {};
  DAYS.forEach((day, index) => {
    const d = new Date(start);
    d.setDate(d.getDate() + index);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    
    dates[day] = {
      label: `${day.charAt(0).toUpperCase() + day.slice(1)} ${d.getMonth() + 1}/${d.getDate()}`,
      dayLabel: day.charAt(0).toUpperCase() + day.slice(1),
      dateLabel: `${d.getMonth() + 1}/${d.getDate()}`,
      fullDate: `${yyyy}-${mm}-${dd}` 
    };
  });
  return dates;
};

// ═══════════════════════════════════════════════════════════════════════════
// UI COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════

interface SearchableDropdownProps {
  value: string;
  onChange: (value: string) => void;
  options: { label: string; value: string }[];
  placeholder: string;
  isLoading?: boolean;
  disabled?: boolean;
}

function SearchableDropdown({ value, onChange, options, placeholder, isLoading, disabled }: SearchableDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [dropdownStyle, setDropdownStyle] = useState<React.CSSProperties>({});
  const wrapperRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setSearch('');
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  // Recalculate position on scroll/resize so fixed dropdown tracks the trigger
  useEffect(() => {
    if (!isOpen) return;
    function updatePosition() {
      if (!wrapperRef.current) return;
      const rect = wrapperRef.current.getBoundingClientRect();
      setDropdownStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: rect.left,
        width: rect.width,
        zIndex: 9999,
      });
    }
    updatePosition();
    window.addEventListener('scroll', updatePosition, true);
    window.addEventListener('resize', updatePosition);
    return () => {
      window.removeEventListener('scroll', updatePosition, true);
      window.removeEventListener('resize', updatePosition);
    };
  }, [isOpen]);

  const openDropdown = () => {
    if (disabled || isLoading) return;
    if (!isOpen && wrapperRef.current) {
      const rect = wrapperRef.current.getBoundingClientRect();
      setDropdownStyle({
        position: 'fixed',
        top: rect.bottom + 4,
        left: rect.left,
        width: rect.width,
        zIndex: 9999,
      });
    }
    setIsOpen(!isOpen);
    setSearch('');
  };

  const filteredOptions = options.filter(opt => 
    opt.label.toLowerCase().includes(search.toLowerCase())
  );

  const displayLabel = options.find(opt => opt.value === value)?.label || value || '';

  return (
    <div ref={wrapperRef} className="relative w-full">
      <div 
        onClick={openDropdown}
        className={`flex items-center justify-between w-full bg-slate-900/50 border rounded p-2 text-sm transition-all select-none
          ${disabled || isLoading ? 'border-slate-700/50 text-slate-500 cursor-not-allowed' : 'border-slate-600 hover:border-blue-500 cursor-pointer text-slate-200'}
          ${isOpen ? 'border-blue-500 ring-1 ring-blue-500/50' : ''}
        `}
      >
        <span className={`truncate mr-2 ${!displayLabel ? 'text-slate-500' : ''}`}>
          {isLoading ? 'Loading...' : (displayLabel || placeholder)}
        </span>
        <ChevronDown className={`w-4 h-4 transition-transform duration-200 flex-shrink-0 ${isOpen ? 'rotate-180 text-blue-400' : 'text-slate-500'}`} />
      </div>

      {isOpen && (
        <div style={dropdownStyle} className="bg-slate-800 border border-slate-600 rounded-lg shadow-2xl overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
          <div className="p-2 border-b border-slate-700 bg-slate-800/50">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input 
                ref={inputRef}
                type="text" 
                className="w-full bg-slate-900 border border-slate-700 rounded px-9 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500 placeholder-slate-500"
                placeholder="Search..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
          </div>
          <ul className="max-h-56 overflow-y-auto py-1 custom-scrollbar">
            {filteredOptions.length === 0 ? (
              <li className="p-3 text-sm text-slate-500 text-center italic">No results found</li>
            ) : (
              filteredOptions.map(opt => (
                <li 
                  key={opt.value}
                  onClick={() => {
                    onChange(opt.value);
                    setIsOpen(false);
                    setSearch('');
                  }}
                  className={`px-3 py-2 text-sm cursor-pointer transition-colors flex items-center justify-between
                    ${value === opt.value ? 'bg-blue-500/20 text-blue-400 font-medium' : 'text-slate-300 hover:bg-slate-700 hover:text-white'}
                  `}
                >
                  <span className="truncate">{opt.label}</span>
                </li>
              ))
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════════

export function TimeTracker() {
  const toast = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // App Initialization State
  const [isInitialized, setIsInitialized] = useState(false);
  const [isConfigured, setIsConfigured] = useState(false);

  // API State
  const [token, setToken] = useState('');
  const [rememberToken, setRememberToken] = useState(true);
  const [showSettings, setShowSettings] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingWeek, setIsLoadingWeek] = useState(false);
  const [isCopyingPrevWeek, setIsCopyingPrevWeek] = useState(false);
  
  // Data State
  const [customers, setCustomers] = useState<ReferenceItem[]>([]);
  const [products, setProducts] = useState<ReferenceItem[]>(DEFAULT_PRODUCTS.map(p => ({ id: p, name: p })));
  const [workTypes, setWorkTypes] = useState<ReferenceItem[]>(DEFAULT_WORK_TYPES.map(w => ({ id: w, name: w })));
  const [isLoadingReferences, setIsLoadingReferences] = useState(false);
  
  // Grid State
  const [weekOffset, setWeekOffset] = useState(0);
  const weekDates = useMemo(() => getDatesForWeekOffset(weekOffset), [weekOffset]);
  const [rows, setRows] = useState<TimeRow[]>([]);

  // 1. Load saved settings & state on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('tt_token');
    
    if (savedToken) {
      setToken(savedToken);
      setRememberToken(true);
      setIsConfigured(true);
    } else {
      setRememberToken(false);
      setIsConfigured(false);
      setRows([{ id: generateId(), customerName: '', productName: '', workTypeName: '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } }]);
    }
    
    setIsInitialized(true);
  }, []);

  // 2. Fetch Reference Data automatically when configured
  useEffect(() => {
    if (isInitialized && isConfigured && token) {
      fetchReferenceData(token);
    }
  }, [isInitialized, isConfigured, token]);

  const fetchReferenceData = async (authToken: string) => {
    setIsLoadingReferences(true);
    try {
      // Fetch Customers (Paginated)
      let allCustomers: ReferenceItem[] = [];
      let page = 1;
      let hasMore = true;

      while (hasMore) {
        const res = await fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl: `https://${API_BASE_DOMAIN}/api/customers?status=active&pageSize=500&page=${page}`,
            token: authToken,
            method: 'GET'
          })
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          if (res.status === 401 || res.status === 403 || data?.message?.includes('Unauthorized')) {
            toast.error('API Token is invalid or expired. Please update settings.');
            setIsConfigured(false); 
            return;
          } else {
            toast.error(`Failed to fetch customers: ${data?.message || res.statusText}`);
          }
          hasMore = false;
          break;
        }

        const data = await res.json();
        const customerList = Array.isArray(data) ? data : (data?.items || []);
        allCustomers = [...allCustomers, ...customerList];

        if (customerList.length < 500) {
          hasMore = false;
        } else {
          page++;
        }
      }

      if (allCustomers.length > 0) {
        const uniqueCustomers = Array.from(new Map(allCustomers.map(c => [c.id, c])).values());
        setCustomers(uniqueCustomers.sort((a, b) => a.name.localeCompare(b.name)));
      }

      // Fetch Products
      try {
        const prodRes = await fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl: `https://${API_BASE_DOMAIN}/api/products`,
            token: authToken,
            method: 'GET'
          })
        });
        if (prodRes.ok) {
          const pData = await prodRes.json();
          const pList = Array.isArray(pData) ? pData : (pData?.items || []);
          if (pList.length > 0) setProducts(pList.sort((a: ReferenceItem, b: ReferenceItem) => a.name.localeCompare(b.name)));
        }
      } catch (e) {
        console.warn("Failed to fetch products dynamically", e);
      }

      // Fetch Work Types
      try {
        const wtRes = await fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl: `https://${API_BASE_DOMAIN}/api/work-types`,
            token: authToken,
            method: 'GET'
          })
        });
        if (wtRes.ok) {
          const wData = await wtRes.json();
          const wList = Array.isArray(wData) ? wData : (wData?.items || []);
          if (wList.length > 0) setWorkTypes(wList.sort((a: ReferenceItem, b: ReferenceItem) => a.name.localeCompare(b.name)));
        }
      } catch (e) {
        console.warn("Failed to fetch work types dynamically", e);
      }

    } catch (e) {
      console.error("Failed to fetch reference data", e);
      toast.error('Network error while fetching reference data.');
    } finally {
      setIsLoadingReferences(false);
    }
  };

  // Helper to fetch ALL time entries robustly (handling pagination up to 100 entries per page)
  const fetchAllWeekEntries = useCallback(async (start: string, end: string, authToken: string) => {
    let allEntries: any[] = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const res = await fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          isExternal: true,
          targetUrl: `https://${API_BASE_DOMAIN}/api/time-entries?startDate=${start}&endDate=${end}&pageSize=100&page=${page}`,
          token: authToken,
          method: 'GET'
        })
      });

      if (!res.ok) {
        if (res.status === 401 || res.status === 403) throw new Error('Unauthorized');
        break;
      }

      const data = await res.json();
      const entries = Array.isArray(data) ? data : (data?.items || data?.data || data?.entries || []);
      allEntries = [...allEntries, ...entries];

      if (entries.length < 100) {
        hasMore = false;
      } else {
        page++;
      }
    }
    return allEntries;
  }, []);

  // 3. Fetch Existing Time Entries for the currently selected week
  const fetchWeekData = useCallback(async () => {
    if (!token || !isConfigured) return;
    
    setIsLoadingWeek(true);
    try {
      const startDate = weekDates.mon.fullDate;
      const endDate = weekDates.sun.fullDate;
      
      const entries = await fetchAllWeekEntries(startDate, endDate, token);
      
      // Group entries into matrix rows
      const grouped: Record<string, TimeRow> = {};
      
      entries.forEach((e: any) => {
        const key = `${e.customerName}|${e.productName}|${e.workTypeName}`;
        
        if (!grouped[key]) {
          grouped[key] = {
            id: generateId(),
            customerName: e.customerName || '',
            productName: e.productName || '',
            workTypeName: e.workTypeName || '',
            hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
          };
        }
        
        // Match the specific day of the week accurately
        const entryDate = e.workDate?.split('T')[0];
        const dayMatch = DAYS.find(d => weekDates[d].fullDate === entryDate);
        if (dayMatch) {
          grouped[key].hours[dayMatch] = String(e.effortHours || '');
        }
      });

      const newRows = Object.values(grouped);
      
      // Ensure there's always at least one empty row to type into
      if (newRows.length === 0) {
        newRows.push({ id: generateId(), customerName: '', productName: '', workTypeName: '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } });
      }
      
      setRows(newRows);
    } catch (error: any) {
      console.error("Failed to load weekly entries", error);
      if (error.message === 'Unauthorized') {
         setIsConfigured(false);
         toast.error('API Token expired. Please update settings.');
      } else {
         toast.error('Failed to load existing timesheet data for this week.');
      }
    } finally {
      setIsLoadingWeek(false);
    }
  }, [token, isConfigured, weekDates, toast, fetchAllWeekEntries]);

  // Fetch week data when the selected week changes or on first load
  useEffect(() => {
    if (isInitialized && isConfigured) {
      fetchWeekData();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [weekOffset, isInitialized, isConfigured]);

  const copyFromPreviousWeek = useCallback(async () => {
    if (!token || !isConfigured) return;
    setIsCopyingPrevWeek(true);
    try {
      const prevWeekDates = getDatesForWeekOffset(weekOffset - 1);
      const entries = await fetchAllWeekEntries(prevWeekDates.mon.fullDate, prevWeekDates.sun.fullDate, token);
      if (entries.length === 0) { toast.info('No time entries found in the previous week to copy.'); return; }
      const seen = new Set<string>();
      const newRows: TimeRow[] = [];
      entries.forEach((e: any) => {
        const key = `${e.customerName}|${e.productName}|${e.workTypeName}`;
        if (!seen.has(key)) {
          seen.add(key);
          newRows.push({ id: generateId(), customerName: e.customerName || '', productName: e.productName || '', workTypeName: e.workTypeName || '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } });
        }
      });
      newRows.sort((a, b) => a.customerName.localeCompare(b.customerName) || a.productName.localeCompare(b.productName) || a.workTypeName.localeCompare(b.workTypeName));
      setRows(newRows);
      toast.success(`Copied ${newRows.length} row(s) from the previous week.`);
    } catch (error: any) {
      if (error.message === 'Unauthorized') { setIsConfigured(false); toast.error('API Token expired. Please update settings.'); }
      else { toast.error('Failed to load previous week data.'); }
    } finally { setIsCopyingPrevWeek(false); }
  }, [token, isConfigured, weekOffset, fetchAllWeekEntries, toast]);

  const saveSettings = () => {
    if (!token) {
      toast.warning('API Token is required.');
      return;
    }

    if (rememberToken) localStorage.setItem('tt_token', token);
    else localStorage.removeItem('tt_token');

    setIsConfigured(true);
    setShowSettings(false);
    toast.success('API Configuration saved');
    fetchReferenceData(token); 
  };

  // Row Management
  const addRow = () => setRows([...rows, { id: generateId(), customerName: '', productName: '', workTypeName: '', hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' } }]);
  const removeRow = (id: string) => setRows(rows.filter(r => r.id !== id));
  const updateRow = (id: string, field: keyof TimeRow, value: any) => setRows(rows.map(r => r.id === id ? { ...r, [field]: value } : r));
  const updateHours = (id: string, day: Day, value: string) => setRows(rows.map(r => r.id === id ? { ...r, hours: { ...r.hours, [day]: value } } : r));

  const resetHours = () => {
    setRows(rows.map(row => ({
      ...row,
      hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
    })));
    toast.success('Hours reset to blank');
  };

  // Totals Calculations
  const getRowTotal = (row: TimeRow) => {
    return DAYS.reduce((sum, day) => sum + (parseFloat(row.hours[day]) || 0), 0);
  };

  const getDayTotal = (day: Day) => {
    return rows.reduce((sum, row) => sum + (parseFloat(row.hours[day]) || 0), 0);
  };

  const getWeeklyTotal = () => {
    return DAYS.reduce((sum, day) => sum + getDayTotal(day), 0);
  };

  // Import / Export
  const exportTemplate = () => {
    const dataToExport = rows.map(({ customerName, productName, workTypeName }) => ({
      customerName, productName, workTypeName, hours: { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
    })); 
    const blob = new Blob([JSON.stringify(dataToExport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'weekly-timesheet-template.json';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Template exported');
  };

  const importTemplate = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const importedData = JSON.parse(event.target?.result as string);
        if (Array.isArray(importedData)) {
          const newRows = importedData.map(r => ({
            id: generateId(),
            customerName: r.customerName || r.customer || '', 
            productName: r.productName || r.product || '',
            workTypeName: r.workTypeName || r.workType || '',
            hours: r.hours || { mon: '', tue: '', wed: '', thu: '', fri: '', sat: '', sun: '' }
          }));
          // Merge imported template rows below existing ones, filtering out entirely empty existing rows
          const filteredExisting = rows.filter(r => r.customerName || r.productName || r.workTypeName || getRowTotal(r) > 0);
          setRows([...filteredExisting, ...newRows]);
          toast.success('Template imported successfully');
        }
      } catch (err) {
        toast.error('Invalid JSON file format');
      }
      if (fileInputRef.current) fileInputRef.current.value = ''; 
    };
    reader.readAsText(file);
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // SUBMISSION LOGIC (With UPSERT support)
  // ═══════════════════════════════════════════════════════════════════════════
  const submitTimesheet = async () => {
    if (!token) {
      toast.error('API Token is required.');
      setIsConfigured(false);
      return;
    }

    // 1. Gather all entries the user has inputted on the screen
    const entriesToProcess: any[] = [];
    let hasValidationErrors = false;

    rows.forEach(row => {
      DAYS.forEach(day => {
        const rawVal = row.hours[day];
        const val = parseFloat(rawVal);
        const hasInput = rawVal !== '' && rawVal !== null && rawVal !== undefined;
        
        if (hasInput) {
          if (!row.customerName || !row.productName || !row.workTypeName) {
            hasValidationErrors = true;
          } else {
            entriesToProcess.push({
              customerName: row.customerName,
              productName: row.productName,
              workTypeName: row.workTypeName,
              workDate: weekDates[day].fullDate,
              effortHours: isNaN(val) ? 0 : val
            });
          }
        }
      });
    });

    if (hasValidationErrors) {
      toast.error('Some entries have hours but are missing Customer, Product, or Work Type.');
      return;
    }

    if (entriesToProcess.length === 0) {
      toast.warning('No hours found to submit.');
      return;
    }

    setIsSubmitting(true);

    // 2. Fetch Existing Entries for the Week to determine POST vs PUT vs DELETE
    let existingEntries: any[] = [];
    try {
      const startDate = weekDates.mon.fullDate;
      const endDate = weekDates.sun.fullDate;
      existingEntries = await fetchAllWeekEntries(startDate, endDate, token);
    } catch (e) {
      console.warn("Could not fetch existing entries, proceeding with POST only.", e);
    }

    // Helper to find ID of existing exact match
    const getExistingEntryId = (cName: string, pName: string, wName: string, date: string) => {
      const found = existingEntries.find(e => 
        e.customerName === cName && 
        e.productName === pName && 
        e.workTypeName === wName && 
        e.workDate && e.workDate.startsWith(date)
      );
      return found?.id || found?._id; 
    };

    let successCount = 0;
    let failCount = 0;

    // 3. Process each entry (Create, Update, or Delete)
    try {
      const requests = entriesToProcess.map(entry => {
        const existingId = getExistingEntryId(entry.customerName, entry.productName, entry.workTypeName, entry.workDate);
        
        let method = 'POST';
        let targetUrl = `https://${API_BASE_DOMAIN}/api/time-entries`;
        let bodyPayload: any = entry;

        if (existingId) {
          if (entry.effortHours > 0) {
            // Update existing entry
            method = 'PUT';
            targetUrl = `https://${API_BASE_DOMAIN}/api/time-entries/${existingId}`;
          } else {
            // Delete existing entry if user cleared the field to 0
            method = 'DELETE';
            targetUrl = `https://${API_BASE_DOMAIN}/api/time-entries/${existingId}`;
            bodyPayload = undefined; 
          }
        } else {
          if (entry.effortHours <= 0) {
            // Field is empty/0 and doesn't exist remotely; skip it safely
            return Promise.resolve({ ok: true, skipped: true });
          }
        }

        return fetch('/api/proxy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isExternal: true,
            targetUrl,
            token: token,
            method,
            body: bodyPayload
          })
        });
      });

      const responses = await Promise.all(requests);
      
      for (const res of responses) {
        if ((res as any).skipped) continue; 
        if (res.ok) successCount++;
        else failCount++;
      }

      if (failCount === 0 && successCount > 0) {
        toast.success(`Successfully processed ${successCount} time entries!`);
        fetchWeekData(); // Refresh table to match DB state perfectly
      } else if (failCount > 0) {
        toast.warning(`Processed ${successCount} entries, but ${failCount} failed.`);
      } else {
        toast.info(`No changes needed to be submitted.`);
      }

    } catch (error: any) {
      toast.error(error.message || 'Failed to submit timesheet');
    } finally {
      setIsSubmitting(false);
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER: LOADING STATE
  // ═══════════════════════════════════════════════════════════════════════════
  if (!isInitialized) {
    return <div className="min-h-screen bg-slate-900 flex items-center justify-center text-blue-400"><Loader2 className="w-8 h-8 animate-spin" /></div>;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER: SETUP REQUIRED SCREEN
  // ═══════════════════════════════════════════════════════════════════════════
  if (!isConfigured) {
    return (
      <div className="min-h-screen bg-slate-900 text-slate-200 flex items-center justify-center p-6">
        <div className="w-full max-w-lg bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
          <div className="p-8 text-center border-b border-slate-700/50 bg-slate-800/80">
            <div className="w-16 h-16 bg-blue-500/10 text-blue-400 rounded-2xl flex items-center justify-center mx-auto mb-4 border border-blue-500/20">
              <Clock className="w-8 h-8" />
            </div>
            <h1 className="text-2xl font-bold text-slate-100">Setup Time Tracker</h1>
            <p className="text-slate-400 mt-2 text-sm">Please provide your secure Bearer Token to access your customers and submit timesheets.</p>
          </div>
          
          <div className="p-8 space-y-6">
            <div className="space-y-3">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-slate-500" /> Bearer Token
              </label>
              <input 
                type="password" 
                value={token} 
                onChange={e => setToken(e.target.value)} 
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-all" 
                placeholder="Paste your timetracker API token..." 
              />
              
              <label className="flex items-center gap-2.5 cursor-pointer mt-2 pl-1 w-max group">
                <input 
                  type="checkbox" 
                  checked={rememberToken}
                  onChange={e => setRememberToken(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-800 cursor-pointer"
                />
                <span className="text-sm text-slate-400 group-hover:text-slate-300 transition-colors select-none">Remember token for future sessions</span>
              </label>
            </div>

            <button 
              onClick={saveSettings} 
              disabled={!token}
              className="w-full flex justify-center items-center gap-2 py-3.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-semibold transition-all active:scale-[0.98]"
            >
              Save Token & Continue
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER: MAIN APP GRID
  // ═══════════════════════════════════════════════════════════════════════════

  const customerOptions = customers.map(c => ({ label: c.name, value: c.name })).sort((a, b) => a.label.localeCompare(b.label));
  const productOptions = products.map(p => ({ label: p.name, value: p.name })).sort((a, b) => a.label.localeCompare(b.label));
  const workTypeOptions = workTypes.map(w => ({ label: w.name, value: w.name })).sort((a, b) => a.label.localeCompare(b.label));

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-4">
      <style>{`
        /* Minimal scrollbar for dropdowns */
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
        
        /* Remove arrows from number inputs */
        input[type="number"].no-spinners::-webkit-inner-spin-button,
        input[type="number"].no-spinners::-webkit-outer-spin-button {
          -webkit-appearance: none;
          margin: 0;
        }
        input[type="number"].no-spinners {
          -moz-appearance: textfield;
        }
      `}</style>
      
      <div className="max-w-[1600px] mx-auto space-y-6 pb-40">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-800/50 p-6 rounded-xl border border-slate-700">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-500/20 text-blue-400 rounded-xl flex items-center justify-center">
              <Clock className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100">Weekly Time Tracker</h1>
              <p className="text-sm text-slate-400">Fill your entire week in a single go</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <input type="file" accept=".json" className="hidden" ref={fileInputRef} onChange={importTemplate} />
            <button onClick={() => fileInputRef.current?.click()} className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors">
              <Upload className="w-4 h-4" /> Import Setup
            </button>
            <button onClick={exportTemplate} className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors">
              <Download className="w-4 h-4" /> Export Setup
            </button>
            <button onClick={() => setShowSettings(!showSettings)} className={`p-2 rounded-lg transition-colors border ${showSettings ? 'bg-blue-500/20 border-blue-500/50 text-blue-400' : 'bg-slate-700 border-slate-600 hover:bg-slate-600'}`}>
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* API Settings Panel (Collapsible) */}
        {showSettings && (
          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 animate-in slide-in-from-top-2">
            <h3 className="text-sm font-semibold text-slate-300 mb-4 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-amber-400" /> Update Configuration
            </h3>
            <div className="flex flex-col md:flex-row gap-4 items-start">
              <div className="flex-1 w-full space-y-2">
                <label className="text-xs text-slate-400 font-medium">Bearer Token</label>
                <input type="password" value={token} onChange={e => setToken(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm focus:border-blue-500 outline-none" placeholder="Paste your timetracker API token..." />
                
                <label className="flex items-center gap-2 cursor-pointer mt-2 pl-1 w-max group">
                  <input 
                    type="checkbox" 
                    checked={rememberToken}
                    onChange={e => setRememberToken(e.target.checked)}
                    className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-900 text-blue-500 focus:ring-blue-500 cursor-pointer"
                  />
                  <span className="text-xs text-slate-400 group-hover:text-slate-300 transition-colors select-none">Remember token</span>
                </label>
              </div>
              <button onClick={saveSettings} className="flex items-center gap-2 px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors mt-6">
                <Save className="w-4 h-4" /> Save Configuration
              </button>
            </div>
          </div>
        )}

        {/* Week Navigator */}
        <div className="flex items-center justify-between bg-slate-800/30 p-4 rounded-xl border border-slate-700/50 relative">
          <button onClick={() => setWeekOffset(w => w - 1)} className="p-2 hover:bg-slate-700 rounded-lg transition-colors"><ChevronLeft className="w-5 h-5" /></button>
          
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">
              Week of {weekDates.mon.label} – {weekDates.sun.label}
            </span>
            <button onClick={fetchWeekData} disabled={isLoadingWeek || isCopyingPrevWeek} className="p-1.5 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded-lg transition-colors ml-2" title="Refresh from Server">
              <RefreshCw className={`w-4 h-4 ${isLoadingWeek ? 'animate-spin' : ''}`} />
            </button>
            <button onClick={copyFromPreviousWeek} disabled={isLoadingWeek || isCopyingPrevWeek} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 border border-amber-500/30 hover:border-amber-400/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed" title="Pre-fill rows from previous week (without hours)">
              {isCopyingPrevWeek ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ChevronLeft className="w-3.5 h-3.5" />}
              Copy Previous Week
            </button>
          </div>
          
          <button onClick={() => setWeekOffset(w => w + 1)} className="p-2 hover:bg-slate-700 rounded-lg transition-colors"><ChevronRight className="w-5 h-5" /></button>
        </div>

        {/* Matrix Grid */}
        <div className={`bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden transition-opacity duration-300 ${isLoadingWeek ? 'opacity-50 pointer-events-none' : 'opacity-100'}`}>
          <div className="overflow-x-auto">
            <div className="w-full">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-800/80 border-b border-slate-700">
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[200px]">Customer</th>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[160px]">Product</th>
                    <th className="p-2 text-xs font-semibold text-slate-400 uppercase tracking-wider w-[155px]">Work Type</th>
                    {DAYS.map(day => (
                      <th key={day} className="p-2 text-xs font-semibold text-center text-slate-400 uppercase tracking-wider w-16">
                        <div>{weekDates[day].dayLabel}</div>
                        <div>{weekDates[day].dateLabel}</div>
                      </th>
                    ))}
                    <th className="p-2 text-xs font-semibold text-center text-slate-400 uppercase tracking-wider w-14 bg-slate-800">Total</th>
                    <th className="p-2 w-10 sticky right-0 bg-slate-800/80"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {rows.map((row) => {
                    const rowTotal = getRowTotal(row);
                    return (
                      <tr key={row.id} className="hover:bg-slate-700/10 transition-colors">
                        <td className="p-2 align-top">
                          <SearchableDropdown 
                            value={row.customerName}
                            onChange={(val) => updateRow(row.id, 'customerName', val)}
                            options={customerOptions}
                            placeholder="Select Customer..."
                            isLoading={isLoadingReferences}
                          />
                        </td>
                        <td className="p-2 align-top">
                          <SearchableDropdown 
                            value={row.productName}
                            onChange={(val) => updateRow(row.id, 'productName', val)}
                            options={productOptions}
                            placeholder="Select Product..."
                            isLoading={isLoadingReferences}
                          />
                        </td>
                        <td className="p-2 align-top">
                          <SearchableDropdown 
                            value={row.workTypeName}
                            onChange={(val) => updateRow(row.id, 'workTypeName', val)}
                            options={workTypeOptions}
                            placeholder="Select Type..."
                            isLoading={isLoadingReferences}
                          />
                        </td>
                        {DAYS.map(day => (
                          <td key={day} className="p-2 align-top">
                            <input 
                              type="number" 
                              min="0" max="24" step="0.25"
                              value={row.hours[day]}
                              onChange={e => updateHours(row.id, day, e.target.value)}
                              className="no-spinners w-full bg-slate-900/50 border border-slate-600 rounded p-1.5 text-sm text-center focus:border-blue-500 focus:bg-slate-900 outline-none transition-all placeholder-slate-600"
                              placeholder="-"
                            />
                          </td>
                        ))}
                        <td className="p-2 text-center align-middle bg-slate-800/30">
                          <span className={`font-mono text-sm font-semibold ${rowTotal > 0 ? 'text-blue-400' : 'text-slate-600'}`}>
                            {rowTotal > 0 ? rowTotal.toFixed(2) : '-'}
                          </span>
                        </td>
                        <td className="p-2 text-center align-middle sticky right-0 bg-slate-900/80 border-l border-slate-700/50">
                          <button onClick={() => removeRow(row.id)} className="text-slate-400 hover:text-red-400 hover:bg-red-400/10 p-1.5 rounded-lg transition-colors" title="Remove Row">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
                <tfoot className="bg-slate-800/80 border-t-2 border-slate-700">
                  <tr>
                    <td colSpan={3} className="p-3 text-right text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Daily Totals
                    </td>
                    {DAYS.map(day => {
                      const dayTotal = getDayTotal(day);
                      return (
                        <td key={day} className="p-3 text-center align-middle">
                          <span className={`font-mono text-sm font-bold ${dayTotal > 0 ? 'text-slate-200' : 'text-slate-600'}`}>
                            {dayTotal > 0 ? dayTotal.toFixed(2) : '-'}
                          </span>
                        </td>
                      );
                    })}
                    <td className="p-3 text-center align-middle bg-blue-500/10 border-l border-r border-slate-700">
                      <span className="font-mono text-sm font-bold text-blue-400">
                        {getWeeklyTotal() > 0 ? getWeeklyTotal().toFixed(2) : '-'}
                      </span>
                    </td>
                    <td></td>
                  </tr>
                  <tr className="border-t border-slate-700/50">
                    <td colSpan={12} className="p-2">
                      <button onClick={addRow} className="flex items-center gap-2 px-4 py-2 text-sm text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded-lg transition-colors">
                        <Plus className="w-4 h-4" /> Add Row
                      </button>
                    </td>
                  </tr>
                </tfoot>
              </table>
            </div>
          </div>
        </div>

        {/* Submit Actions */}
        <div className="flex justify-between items-center pt-4">
          <button 
            onClick={resetHours} 
            disabled={isSubmitting || isLoadingWeek}
            className="flex items-center gap-2 px-6 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-medium transition-all"
          >
            <RotateCcw className="w-4 h-4" />
            Reset Hours
          </button>
          
          <button 
            onClick={submitTimesheet} 
            disabled={isSubmitting || isLoadingWeek}
            className="flex items-center gap-2 px-8 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl font-semibold shadow-lg shadow-emerald-900/20 transition-all active:scale-95"
          >
            {isSubmitting ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
            Submit Timesheet for Week
          </button>
        </div>

      </div>
    </div>
  );
}