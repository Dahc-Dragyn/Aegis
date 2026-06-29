"use client";

import React, { useState, useEffect, useRef, useMemo } from 'react';
import IngestionManifold from '@/components/IngestionManifold';
import ArtifactVault from '@/components/ArtifactVault';
import ProvenanceGraph from '@/components/ProvenanceGraph';
import { 
  Shield, Zap, Activity, Target, AlertCircle, Terminal, Database, Unlock, Lock, ChevronRight, Network, HelpCircle, X, Info, RefreshCw, Download, Eye, Maximize2, RotateCcw, Filter, Search
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { List } from 'react-window';
import { AutoSizer as _AutoSizer } from 'react-virtualized-auto-sizer';
const AutoSizer = _AutoSizer as any;
import dynamic from 'next/dynamic';

import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

const ResponsiveGridLayout = dynamic(
  async () => {
    const mod = await import('react-grid-layout/legacy');
    const Responsive = mod.Responsive;
    const WidthProvider = mod.WidthProvider;
    
    if (!WidthProvider || !Responsive) {
      throw new Error("FAILED_TO_LOAD_RGL_LEGACY_COMPONENTS");
    }
    
    const Component = WidthProvider(Responsive);
    return (props: any) => <Component {...props} />;
  },
  { ssr: false }
);

const DEFAULT_LAYOUTS: any = {
  lg: [
    { i: 'vitals', x: 0, y: 0, w: 3, h: 4, minW: 2, minH: 3 },
    { i: 'vault', x: 0, y: 4, w: 3, h: 8, minW: 2, minH: 4 },
    { i: 'sitrep', x: 3, y: 0, w: 6, h: 4, minW: 4, minH: 2 },
    { i: 'intelligence', x: 3, y: 4, w: 6, h: 8, minW: 4, minH: 4 },
    { i: 'manifold', x: 9, y: 0, w: 3, h: 4, minW: 2, minH: 3 },
    { i: 'overwatch', x: 9, y: 4, w: 3, h: 3, minW: 2, minH: 2 },
    { i: 'killchain', x: 9, y: 7, w: 3, h: 5, minW: 2, minH: 3 },
  ]
};

interface TelemetryEntry {
  timestamp: string;
  event?: string;
  message?: string;
  severity: 'hostile' | 'warning' | 'friendly' | 'neutral' | 'critical';
  details?: string;
  node_id?: string;
  ingestion_timestamp?: string;
  pid?: string;
}

const TacticalPane = React.forwardRef(({ style, className, onMouseDown, onMouseUp, onTouchEnd, children, title, icon: Icon, ...props }: any, ref: any) => {
  return (
    <div 
      ref={ref} 
      style={style} 
      className={`pane flex flex-col bg-slate-900 border border-slate-800 shadow-xl ${className}`}
      onMouseDown={onMouseDown}
      onMouseUp={onMouseUp}
      onTouchEnd={onTouchEnd}
      {...props}
    >
      <div className="pane-header shrink-0 cursor-grab active:cursor-grabbing drag-handle select-none flex items-center justify-between px-4 py-2 bg-slate-950/50 border-b border-slate-800">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="w-3 h-3 text-cyan-500" />}
          <span className="text-[10px] font-black uppercase tracking-[0.2em]">{title}</span>
        </div>
        <div className="flex gap-1">
           <div className="w-1.5 h-1.5 rounded-full bg-slate-800" />
           <div className="w-1.5 h-1.5 rounded-full bg-slate-800" />
        </div>
      </div>
      <div className="flex-1 min-h-0 relative overflow-hidden">
        {children}
      </div>
      <div className="absolute bottom-0 right-0 w-2 h-2 border-r border-b border-cyan-500/30 pointer-events-none" />
    </div>
  );
});
TacticalPane.displayName = 'TacticalPane';

function TacticalHUD() {
  const [telemetry, setTelemetry] = useState<TelemetryEntry[]>([]);
  const [sitrep, setSitrep] = useState("ANALYZING MANIFOLD... WAITING FOR INGESTION.");
  const [displayedSitrep, setDisplayedSitrep] = useState("");
  const [hubStatus, setHubStatus] = useState("OFFLINE");
  const [isOffline, setIsOffline] = useState(false);
  const [isIsolated, setIsIsolated] = useState(false);
  const [showGate, setShowGate] = useState(false);
  const [isHunting, setIsHunting] = useState(false);
  const [showHuntAlert, setShowHuntAlert] = useState(false);
  const [activeView, setActiveView] = useState<'stream' | 'graph'>('stream');
  const [feedMode, setFeedMode] = useState<'tactical' | 'forensic'>('tactical');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [pidFilter, setPidFilter] = useState<string | null>(null);
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [layouts, setLayouts] = useState<any>(DEFAULT_LAYOUTS);
  const [clarity, setClarity] = useState({ ingested: 0, suppressed: 0, clarity: 100 });
  const [isTheaterExpanded, setIsTheaterExpanded] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('aegis-hud-layout');
    if (saved) {
      try {
        setLayouts(JSON.parse(saved));
      } catch (e) {
        console.error("[HUD] LAYOUT_RESTORE_ERROR:", e);
      }
    }
  }, []);
  const typingIdx = useRef(0);

  const resetLayout = () => {
    if (confirm("RESTORE DEFAULT MISSION LAYOUT? Current mosaic configuration will be lost.")) {
      localStorage.removeItem('aegis-hud-layout');
      setLayouts(DEFAULT_LAYOUTS);
    }
  };

  // 1. TYPING ANIMATION
  useEffect(() => {
    setDisplayedSitrep("");
    typingIdx.current = 0;
    
    // Add Node Context if filtered
    let finalSitrep = sitrep;
    if (pidFilter) {
      finalSitrep = `## 🛰️ NODE CONTEXT: PID ${pidFilter}\n\n` + 
                    `**ANALYSIS:** Focused telemetry shows active process lineage for PID ${pidFilter}. ` +
                    `All associated network activity and child processes are being prioritized in the Intelligence Stream.\n\n` +
                    `---\n\n` + sitrep;
    }

    const interval = setInterval(() => {
      if (typingIdx.current < finalSitrep.length) {
        setDisplayedSitrep(prev => prev + finalSitrep[typingIdx.current]);
        typingIdx.current++;
      } else {
        clearInterval(interval);
      }
    }, 10);
    return () => clearInterval(interval);
  }, [sitrep, pidFilter]);

  // 2. DATA FETCHING
  const refreshData = async () => {
    try {
      const t = Date.now();
      const [histRes, sitRes, isoRes, healthRes, statusRes] = await Promise.all([
        fetch(`/telemetry/history?t=${t}`),
        fetch(`/sitrep?t=${t}`),
        fetch(`/isolation/status?t=${t}`),
        fetch(`/system/health?t=${t}`),
        fetch(`/system/status?t=${t}`)
      ]);
      if (histRes.ok) {
        const histData = await histRes.json();
        // Extract PID for filtering if possible
        const mappedData = histData.map((l: any) => {
           const pid = l.details?.match(/PID: (\d+)/)?.[1] || l.pid || l.metadata?.ProcessId;
           const details = l.details || l.message || (l.metadata ? JSON.stringify(l.metadata) : "");
           return { ...l, pid, details };
        });
        setTelemetry(mappedData);
        setHubStatus("ONLINE");
      } else {
        throw new Error("EXFIL_BRIDGE_FAILED");
      }
      if (sitRes.ok) {
        const sitData = await sitRes.json();
        setSitrep(sitData.sitrep);
        
        if (sitData.sitrep.includes("AUTO-EXPAND") && !isTheaterExpanded) {
            setIsTheaterExpanded(true);
        }
      }
      if (isoRes.ok) {
        const isoData = await isoRes.json();
        setIsIsolated(isoData.isolated);
      }
      if (healthRes.ok) {
        const healthData = await healthRes.json();
        setClarity(healthData);
      }
      if (statusRes.ok) {
        const statusData = await statusRes.json();
        setIsOffline(statusData.offline_mode);
      }
    } catch (e: any) {
      setHubStatus("OFFLINE");
      console.error("[HUD] SYNC_ERROR:", e);
    }
  };

  useEffect(() => {
    refreshData();
    const poll = setInterval(refreshData, 5000);
    return () => clearInterval(poll);
  }, []);

  // 3. ACTION HANDLERS
  const handleSnapshot = async () => {
    if (isHunting) return;
    setIsHunting(true);
    setShowHuntAlert(true);
    try {
      await fetch('/snapshot', { method: 'POST' });
      setTimeout(refreshData, 500);
    } catch (e) {
      console.error("[HUD] SNAPSHOT_ERROR:", e);
    } finally {
      setTimeout(() => {
        setIsHunting(false);
        setShowHuntAlert(false);
        refreshData();
      }, 5000);
    }
  };

  const handleToggleIsolation = async (controlId?: string) => {
    await fetch('/isolation/toggle', { method: 'POST' });
    setShowGate(false);
    refreshData();
    if (controlId) {
      console.log(`[KILLCHAIN] NIST CONTROL ${controlId} SATISFIED`);
    }
  };

  const onLayoutChange = (currentLayout: any[], allLayouts: any) => {
    setLayouts(allLayouts);
    localStorage.setItem('aegis-hud-layout', JSON.stringify(allLayouts));
  };

  // 4. DATA PROCESSING (TACTICAL FILTER)
  const processedTelemetry = useMemo(() => {
    let base = telemetry;
    if (pidFilter) {
      base = base.filter(l => l.pid === pidFilter);
    }

    if (feedMode === 'forensic') return base;
    
    const results: any[] = [];
    let currentSummary: any = null;

    base.forEach((log) => {
      const isNoiseSummary = log.message?.includes("NOISE DETECTED");
      const sev = log.severity?.toLowerCase();
      const isCritical = sev === 'hostile' || sev === 'critical' || sev === 'warning' || isNoiseSummary;
      
      if (isCritical) {
        if (currentSummary) {
          results.push(currentSummary);
          currentSummary = null;
        }
        
        if (isNoiseSummary) {
          results.push({ ...log, type: 'noise_alert' });
        } else {
          results.push(log);
        }
      } else {
        if (!currentSummary) {
          currentSummary = { 
            type: 'summary', 
            count: 1, 
            timestamp: log.timestamp, 
            severity: 'neutral',
            event: 'NOMINAL SIGNALS SUPPRESSED'
          };
        } else {
          currentSummary.count++;
        }
      }
    });

    if (currentSummary) results.push(currentSummary);
    return results;
  }, [telemetry, feedMode, pidFilter]);

  const activeNodes = useMemo(() => {
    const nodes = new Map<string, boolean>();
    const now = Date.now();
    telemetry.forEach(log => {
      if (!log.node_id) return;
      const logTime = new Date(log.ingestion_timestamp || log.timestamp).getTime();
      if (now - logTime < 60000) {
        nodes.set(log.node_id, true);
      } else if (!nodes.has(log.node_id)) {
        nodes.set(log.node_id, false);
      }
    });
    return nodes;
  }, [telemetry]);

  // 5. CROSS-POLLINATION HANDLERS
  const handleNodeSelect = (pid: string | null) => {
    setSelectedNodeId(pid);
    setPidFilter(pid);
    if (pid) {
      // Trigger a visual "ping" in the UI
      console.log(`[HUD] FOCUS_PIVOT: PID ${pid} ENGAGED`);
      setActiveView('stream');
    }
  };

  return (
    <main className="h-screen w-screen bg-black text-slate-300 flex flex-col p-3 overflow-hidden font-mono selection:bg-cyan-500/30">
      
      {/* 1. TACTICAL ALERT OVERLAY */}
      {showHuntAlert && (
        <div className="fixed inset-0 z-[200] flex items-center justify-center pointer-events-none">
          <div className="bg-cyan-950/40 border border-cyan-500/50 backdrop-blur-md px-12 py-8 rounded-lg animate-pulse flex flex-col items-center gap-4">
             <Target className="w-12 h-12 text-cyan-400" />
             <div className="text-center">
                <h2 className="text-2xl font-black tracking-tighter text-white uppercase italic">Active Host Hunt</h2>
                <p className="text-cyan-400 text-[10px] tracking-[0.3em] font-bold mt-1">DISPATCHING AEGIS SENTINEL ENGINE</p>
             </div>
          </div>
        </div>
      )}

      {/* SAFETY GATE MODAL */}
      {showGate && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/80 backdrop-blur-sm">
          <div className="w-96 bg-slate-900 border border-rose-500/50 p-6 rounded-lg shadow-2xl">
            <div className="flex items-center gap-3 text-rose-500 mb-4">
              <AlertCircle className="w-6 h-6" />
              <h2 className="font-bold uppercase tracking-widest text-sm">Confirm Isolation?</h2>
            </div>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              WARNING: Activating the Defensive Lock will restrict all non-management outbound traffic. This will contain active exfiltration but may disrupt host services.
            </p>
            <div className="flex gap-3">
              <button onClick={() => setShowGate(false)} className="flex-1 bg-slate-800 text-slate-300 text-[10px] font-bold py-2 rounded uppercase tracking-widest hover:bg-slate-700 transition-colors">Cancel</button>
              <button onClick={() => handleToggleIsolation("SC-7")} className="flex-1 bg-rose-600 text-white text-[10px] font-bold py-2 rounded uppercase tracking-widest hover:bg-rose-500 transition-colors">Execute Lock</button>
            </div>
          </div>
        </div>
      )}

      {/* MISSION MANUAL MODAL */}
      {isHelpOpen && (
        <div className="fixed inset-0 z-[300] flex items-center justify-center p-4 sm:p-20">
          <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-md" onClick={() => setIsHelpOpen(false)} />
          <div className="relative w-full max-w-4xl max-h-full overflow-y-auto bg-slate-900 border border-cyan-500/30 rounded-lg shadow-2xl flex flex-col custom-scrollbar">
            <div className="sticky top-0 z-10 bg-slate-900 border-b border-white/10 px-8 py-6 flex justify-between items-start">
              <div>
                <h3 className="text-cyan-400 font-black text-lg uppercase tracking-[0.3em] mb-1">Mission Operating Manual</h3>
                <p className="text-slate-500 text-xs font-mono">AEGIS C4ISR // TILED HUD MOSAIC PROTOCOL</p>
              </div>
              <button onClick={() => setIsHelpOpen(false)} className="p-2 hover:bg-white/10 rounded-full transition-colors">
                <X className="w-6 h-6 text-slate-400" />
              </button>
            </div>
            <div className="p-8 space-y-12">
               <div className="grid grid-cols-2 gap-12 text-xs">
                 <div className="space-y-4">
                   <h4 className="text-cyan-100 font-bold uppercase tracking-widest border-l-2 border-cyan-500 pl-3">Phase 1: Ingestion</h4>
                   <p className="text-slate-400 leading-relaxed">
                     <span className="text-cyan-500 font-bold">Artifact Upload:</span> Drag and drop EVTX or JSONL artifacts into the Manifold. Aegis will automatically decompress and vault the signals.
                     <br /><br />
                     <span className="text-cyan-500 font-bold">Real-time Stream:</span> Intelligence is hydrated instantly into the stream.
                   </p>
                 </div>
                 <div className="space-y-4">
                   <h4 className="text-rose-400 font-bold uppercase tracking-widest border-l-2 border-rose-500 pl-3">Phase 2: Analysis</h4>
                   <p className="text-slate-400 leading-relaxed">
                     <span className="text-rose-500 font-bold">Cross-Pollination:</span> Select a node in the Provenance Graph to filter the Intelligence Stream for that specific process lineage.
                     <br /><br />
                     <span className="text-rose-500 font-bold">Sitrep Guidance:</span> The Commander's Sitrep identifies attack chains and provides interactive response buttons.
                   </p>
                 </div>
                 <div className="space-y-4">
                   <h4 className="text-emerald-400 font-bold uppercase tracking-widest border-l-2 border-emerald-500 pl-3">Phase 3: Response</h4>
                   <p className="text-slate-400 leading-relaxed">
                     <span className="text-emerald-500 font-bold">Kill Chain:</span> Use the 'Isolate Host' command to restrict network traffic or 'Deploy Hunt' to trigger deep memory forensics.
                     <br /><br />
                     <span className="text-emerald-500 font-bold">Compliance:</span> All actions satisfy NIST-800-53 controls (SC-7, SI-4).
                   </p>
                 </div>
                 <div className="space-y-4">
                   <h4 className="text-amber-400 font-bold uppercase tracking-widest border-l-2 border-amber-500 pl-3">System Vitals</h4>
                   <p className="text-slate-400 leading-relaxed">
                     Monitor engine latency and signal clarity. A drop in clarity indicates high noise-to-signal ratio, requiring manual SNR adjustment or filter application.
                   </p>
                 </div>
               </div>
            </div>
            <div className="sticky bottom-0 bg-slate-900 px-8 py-4 border-t border-white/5 text-center">
              <button onClick={() => setIsHelpOpen(false)} className="bg-cyan-600 hover:bg-cyan-500 text-black font-black text-[10px] uppercase tracking-[0.4em] px-12 py-3 rounded transition-all">Return to Mission</button>
            </div>
          </div>
        </div>
      )}

      {/* 1. TOP COMMAND BAR */}
      <header className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3 h-14 shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-500" />
            <h1 className="text-xl font-black tracking-tighter text-white">AEGIS <span className="text-cyan-500 font-light text-sm tracking-widest ml-1">C4ISR</span></h1>
          </div>
          <div className="flex items-center gap-4 text-[10px] tracking-widest uppercase font-bold">
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Sentinel:</span>
              <span className="text-emerald-500 animate-pulse">Active</span>
            </div>
            <div className="flex items-center gap-2 border-l border-slate-800 pl-4">
              <span className="text-slate-500">Network:</span>
              <span className={isIsolated ? "text-rose-500" : "text-cyan-500"}>{isIsolated ? "Restricted" : "Open"}</span>
            </div>
            {pidFilter && (
              <div className="flex items-center gap-2 border-l border-slate-800 pl-4">
                <div className="bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded flex items-center gap-1.5">
                  <Filter className="w-2.5 h-2.5 text-cyan-500" />
                  <span className="text-cyan-500 font-black text-[9px] tracking-widest">PID FILTER: {pidFilter}</span>
                  <button onClick={() => handleNodeSelect(null)} className="ml-1 hover:text-white transition-colors"><X className="w-2.5 h-2.5" /></button>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
           <button onClick={resetLayout} className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded text-[10px] font-bold text-slate-400 hover:text-rose-400 transition-colors uppercase tracking-widest" title="Snap Back to Default Layout">
              <RefreshCw className="w-3 h-3" />
              Reset Layout
           </button>
           <button onClick={() => setIsHelpOpen(true)} className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded text-[10px] font-bold text-slate-400 hover:text-cyan-400 transition-colors uppercase tracking-widest">
              <HelpCircle className="w-3 h-3" />
              Manual
           </button>
           <div className="bg-rose-950/20 border border-rose-900/50 px-4 py-1 text-[9px] font-bold text-rose-500 tracking-[0.2em] uppercase">
             User Responsible For All Outputs // NIST-800-53
           </div>
        </div>
      </header>

      {/* 2. TILED HUD MOSAIC */}
      <div className="flex-1 min-h-0 relative overflow-hidden">
        <style jsx global>{`
          .react-resizable-handle { background: none !important; z-index: 50 !important; }
          .react-resizable-handle-se::after { right: 2px; bottom: 2px; width: 10px; height: 10px; border-right: 2px solid #06b6d4; border-bottom: 2px solid #06b6d4; background: none; content: ""; position: absolute; opacity: 0.2; transition: opacity 0.2s; }
          .react-resizable-handle:hover::after { opacity: 1; }
          .custom-scrollbar::-webkit-scrollbar { width: 4px; }
          .custom-scrollbar::-webkit-scrollbar-track { background: #020617; }
          .custom-scrollbar::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 2px; }
          .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #334155; }
          .scrollbar-none::-webkit-scrollbar { display: none; }
          .pane { position: relative; overflow: hidden; }
          .pane::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, rgba(6, 182, 212, 0.2), transparent); animation: scan-line 4s linear infinite; pointer-events: none; z-index: 10; }
          @keyframes scan-line {
            0% { top: 0; }
            100% { top: 100%; }
          }
        `}</style>
        <ResponsiveGridLayout
          className="layout"
          layouts={layouts}
          breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
          cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
          rowHeight={50}
          draggableHandle=".drag-handle"
          onLayoutChange={onLayoutChange}
          margin={[12, 12]}
          isResizable={true}
          isDraggable={true}
          compactType={null}
          preventCollision={true}
          resizeHandles={['s', 'e', 'se']}
        >
          {/* SYSTEM VITALS */}
          <div key="vitals">
            <TacticalPane title="System Vitals" icon={Activity}>
              <div className="p-4 space-y-6 overflow-y-auto h-full scrollbar-none">
                <div className="space-y-2">
                  <div className="flex justify-between text-[10px] uppercase tracking-widest font-bold">
                    <span className="text-slate-400">Engine Latency</span>
                    <span className="text-cyan-400">{(clarity as any).latency || '0.42ms'}</span>
                  </div>
                  <div className="h-1 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-500/50" style={{ width: `${Math.min(100, (clarity as any).ingested / 100)}%` }} />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="flex flex-col gap-1">
                    <span className="text-[8px] text-slate-500 uppercase tracking-widest font-bold">Signals Ingested</span>
                    <span className="text-sm text-white font-black">{(clarity as any).ingested.toLocaleString()}</span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-[8px] text-slate-500 uppercase tracking-widest font-bold">Noise Suppressed</span>
                    <span className="text-sm text-slate-400 font-black">{(clarity as any).suppressed.toLocaleString()}</span>
                  </div>
                </div>

                <div className="space-y-2 text-center py-4 border border-dashed border-slate-800 rounded">
                   <p className="text-[8px] text-slate-500 uppercase tracking-widest">Signal Clarity Index</p>
                   <div className="text-xl font-black text-cyan-500 italic">{(clarity as any).clarity}%</div>
                   <div className="flex justify-center gap-1 mt-2">
                      {[1,2,3,4,5,6,7,8].map(i => (
                        <div key={i} className={`w-3 h-1 rounded-sm ${i > 6 ? 'bg-rose-500/40 animate-pulse' : 'bg-cyan-500/20'}`} />
                      ))}
                   </div>
                </div>
              </div>
            </TacticalPane>
          </div>

          {/* ARTIFACT VAULT */}
          <div key="vault">
            <TacticalPane title="Active Intelligence" icon={Database}>
              <ArtifactVault />
            </TacticalPane>
          </div>
          
          {/* SITREP */}
          <div key="sitrep">
            <TacticalPane title="Commander's Sitrep" icon={ChevronRight}>
              <div className="flex flex-col h-full bg-slate-900/40">
                <div className="flex-1 p-6 overflow-y-auto custom-scrollbar">
                  <div className="prose prose-invert prose-cyan max-w-none">
                    <ReactMarkdown 
                      remarkPlugins={[remarkGfm]}
                      components={{
                        h1: ({node, ...props}) => <h1 className="text-xl font-black uppercase tracking-tighter border-b border-cyan-500/30 pb-2 mb-4 text-white" {...props} />,
                        h2: ({node, ...props}) => <h2 className="text-md font-bold uppercase tracking-widest text-cyan-400 mt-6 mb-2 border-l-2 border-cyan-500 pl-3" {...props} />,
                        blockquote: ({node, ...props}: any) => {
                           const content = props.children?.[1]?.props?.children?.[0] || "";
                           if (content.includes("IMMEDIATE ACTION")) {
                             return (
                               <div className="bg-rose-950/20 border border-rose-500/30 p-4 rounded-lg my-6 animate-in slide-in-from-left duration-500">
                                 <div className="flex items-center gap-2 text-rose-500 font-black text-xs uppercase tracking-widest mb-2">
                                   <Zap className="w-4 h-4 animate-pulse" /> Recommended Action
                                 </div>
                                 <p className="text-xs text-rose-200 mb-4">{content.replace("IMMEDIATE ACTION: ", "")}</p>
                                 <div className="flex gap-2">
                                    <button 
                                      onClick={() => handleToggleIsolation("SC-7")}
                                      className={`text-[9px] font-black uppercase px-4 py-2 rounded transition-all shadow-lg ${
                                        isIsolated ? 'bg-emerald-600 text-white' : 'bg-rose-600 hover:bg-rose-500 text-white'
                                      }`}
                                    >
                                      {isIsolated ? "Isolation Active [SC-7]" : "Execute Isolation [SC-7]"}
                                    </button>
                                    <button 
                                      onClick={handleSnapshot}
                                      className="bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[9px] font-black uppercase px-4 py-2 rounded transition-all"
                                    >
                                      Deploy Hunt [SI-4]
                                    </button>
                                 </div>
                               </div>
                             );
                           }
                           return <blockquote className="border-l-4 border-cyan-500/30 pl-4 italic text-slate-400" {...props} />;
                        },
                        li: ({node, ...props}) => (
                          <li className="flex items-start gap-2 text-[11px] text-slate-400 font-mono mb-1">
                            <span className="text-cyan-500 shrink-0 mt-1">▸</span>
                            <span>{props.children}</span>
                          </li>
                        ),
                      }}
                    >
                      {displayedSitrep}
                    </ReactMarkdown>
                  </div>
                </div>
              </div>
            </TacticalPane>
          </div>

          {/* INTELLIGENCE STREAM */}
          <div key="intelligence">
            <TacticalPane title={activeView === 'stream' ? "Intelligence Stream" : "Provenance Graph"} icon={activeView === 'stream' ? Activity : Network}>
              <div className="flex flex-col h-full overflow-hidden">
                <div className="shrink-0 bg-slate-950/50 border-b border-slate-800 p-2 flex justify-between items-center">
                  <div className="flex gap-1 bg-black p-1 border border-slate-800 rounded">
                    <button 
                      onClick={() => setActiveView('stream')}
                      className={`px-3 py-1 text-[8px] font-black uppercase tracking-widest transition-all ${activeView === 'stream' ? 'bg-cyan-500 text-black' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                      STREAM
                    </button>
                    <button 
                      onClick={() => setActiveView('graph')}
                      className={`px-3 py-1 text-[8px] font-black uppercase tracking-widest transition-all ${activeView === 'graph' ? 'bg-cyan-500 text-black' : 'text-slate-500 hover:text-slate-300'}`}
                    >
                      GRAPH
                    </button>
                  </div>

                  <div className="flex gap-1 bg-black p-1 border border-slate-800 rounded">
                    <button 
                      onClick={() => setFeedMode('tactical')}
                      className={`px-3 py-1 text-[8px] font-black uppercase tracking-widest transition-all ${feedMode === 'tactical' ? 'bg-emerald-600 text-white' : 'text-slate-500 hover:text-slate-300'}`}
                      title="Show Critical Alerts & Summaries"
                    >
                      TACTICAL
                    </button>
                    <button 
                      onClick={() => setFeedMode('forensic')}
                      className={`px-3 py-1 text-[8px] font-black uppercase tracking-widest transition-all ${feedMode === 'forensic' ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-300'}`}
                      title="Show Raw Forensic Stream"
                    >
                      FORENSIC
                    </button>
                  </div>
                  {pidFilter && (
                    <div className="flex items-center gap-2 text-[8px] text-cyan-500 font-bold uppercase animate-pulse">
                      <Filter className="w-2.5 h-2.5" /> Filtering by PID {pidFilter}
                    </div>
                  )}
                </div>

                <div className="flex-1 relative">
                  {activeView === 'stream' ? (
                    <div className="absolute inset-0 overflow-y-auto custom-scrollbar p-1">
                      {processedTelemetry.length === 0 ? (
                        <div className="flex items-center justify-center h-full text-slate-700 text-[10px] uppercase tracking-widest italic animate-pulse">
                          No signals detected in current manifold
                        </div>
                      ) : (
                        processedTelemetry.map((log: any, index: number) => {
                          if (log.type === 'summary') {
                            return (
                              <div key={`sum-${index}`} className="flex items-center gap-3 px-4 py-3 border-b border-slate-800 bg-slate-950/20">
                                <span className="text-slate-600 text-[9px]">[{log.timestamp}]</span>
                                <div className="h-px flex-1 bg-slate-800" />
                                <span className="text-[9px] font-bold text-slate-500 tracking-tighter italic uppercase">
                                  {log.count} Signals Suppressed (UI Level)
                                </span>
                                <div className="h-px flex-1 bg-slate-800" />
                              </div>
                            );
                          }
                          
                          const eventName = log.event || log.message || "UNKNOWN_EVENT";
                          const sev = log.severity?.toLowerCase();
                          const isCritical = sev === 'hostile' || sev === 'critical';
                          
                          return (
                            <div 
                              key={index}
                              onClick={() => handleNodeSelect(log.pid || null)}
                              className={`flex items-start gap-3 p-3 border-b text-[10px] cursor-pointer hover:bg-white/5 transition-colors border-slate-800 
                                ${isCritical ? 'bg-rose-500/10 border-l-2 border-l-rose-500' : ''} 
                                ${pidFilter && log.pid === pidFilter ? 'bg-cyan-500/10 border-l-2 border-l-cyan-500' : ''}`}
                            >
                              <span className="text-slate-600 shrink-0 w-16 font-mono">[{log.timestamp}]</span>
                              <div className="flex flex-col shrink-0 w-32 gap-1">
                                <span className={`font-bold tracking-tighter uppercase ${
                                  isCritical ? 'text-rose-500' : 'text-blue-400'
                                }`}>
                                  {eventName}
                                </span>
                                <span className="text-[8px] text-slate-500">PID: {log.pid || 'N/A'}</span>
                              </div>
                              <span className="text-slate-300 truncate flex-1 leading-relaxed">{log.details}</span>
                            </div>
                          );
                        })
                      )}
                    </div>
                  ) : (
                    <div className="absolute inset-0">
                      <AutoSizer>
                        {({ height, width }: any) => (
                          <ProvenanceGraph 
                            highlightNodeId={selectedNodeId} 
                            width={width} 
                            height={height} 
                            onNodeClick={(pid: string) => handleNodeSelect(pid)}
                          />
                        )}
                      </AutoSizer>
                    </div>
                  )}
                </div>
              </div>
            </TacticalPane>
          </div>

          <div key="manifold">
            <TacticalPane title="Ingestion Manifold" icon={Terminal}>
              <IngestionManifold onComplete={refreshData} />
            </TacticalPane>
          </div>

          <div key="overwatch">
            <TacticalPane title="Overwatch Status" icon={Shield}>
              <div className="p-4 space-y-4">
                <div className="flex flex-col gap-1">
                  <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold">Signal density</span>
                  <div className="flex items-baseline gap-2">
                    <span className="text-xl text-white font-black">{Math.floor(telemetry.length / 10)}</span>
                    <span className="text-[8px] text-slate-600 font-bold uppercase tracking-widest">Events / Sec</span>
                  </div>
                </div>

                <div className="flex flex-col gap-1 border-t border-slate-800 pt-3">
                  <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold">Response Posture</span>
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${isIsolated ? 'bg-rose-500 shadow-[0_0_8px_#f43f5e]' : 'bg-emerald-500 animate-pulse'}`} />
                    <span className={isIsolated ? "text-rose-500 text-xs font-black uppercase" : "text-emerald-500 text-xs font-black uppercase"}>
                      {isIsolated ? "ACTIVE_ISOLATION" : "PASSIVE_MONITORING"}
                    </span>
                  </div>
                </div>

                <div className="flex flex-col gap-1 border-t border-slate-800 pt-3">
                  <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold">Threat Context</span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {telemetry.some(l => {
                      const s = l.severity?.toLowerCase();
                      return s === 'hostile' || s === 'critical';
                    }) 
                      ? "⚠️ HOSTILE_SIGNALS_PRESENT" 
                      : "✓ NO_IMMEDIATE_THREATS"}
                  </span>
                </div>
              </div>
            </TacticalPane>
          </div>

          <div key="killchain">
            <TacticalPane title="Kill Chain Response" icon={Zap}>
              <div className="p-4 space-y-3">
                <button 
                  onClick={handleSnapshot}
                  disabled={isHunting}
                  className={`w-full border text-[10px] font-bold py-3 rounded uppercase tracking-widest transition-all flex items-center justify-center gap-2 ${
                    isHunting 
                      ? 'bg-cyan-950 border-cyan-500 text-cyan-400 animate-pulse cursor-wait' 
                      : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  <Target className={`w-4 h-4 ${isHunting ? 'animate-spin' : ''}`} />
                  Deploy Host Hunt [SI-4]
                </button>
                
                <button 
                  onClick={() => setShowGate(true)}
                  className={`w-full border text-[10px] font-bold py-3 rounded uppercase tracking-widest transition-colors flex items-center justify-center gap-2 ${
                    isIsolated 
                      ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-500 hover:bg-emerald-500/10' 
                      : 'bg-rose-950/30 border-rose-500/50 text-rose-500 hover:bg-rose-500/10'
                  }`}
                >
                  {isIsolated ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                  {isIsolated ? 'Restore Network' : 'Isolate Host [SC-7]'}
                </button>
              </div>
            </TacticalPane>
          </div>
        </ResponsiveGridLayout>
      </div>

      <footer className="mt-3 flex justify-between items-center text-[9px] uppercase tracking-[0.2em] text-slate-600 font-bold h-8 shrink-0 border-t border-slate-900 pt-2">
        <div className="flex gap-4">
          <span>Latency: 0.42ms // Tunnel: AES-256 GCM</span>
          <span className="text-cyan-950">|</span>
          <span className={hubStatus === "ONLINE" ? "text-cyan-500" : "text-rose-500 animate-pulse"}>
            Hub Status: {hubStatus}
          </span>
        </div>
        <div>Aegis Tactical Manifold V4.0 // PHASE 1 PIVOT</div>
      </footer>
    </main>
  );
}

export default TacticalHUD;

