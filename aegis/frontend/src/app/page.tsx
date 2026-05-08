"use client";

import React, { useState, useEffect, useRef } from 'react';
import IngestionManifold from '@/components/IngestionManifold';
import ArtifactVault from '@/components/ArtifactVault';
import ProvenanceGraph from '@/components/ProvenanceGraph';
import { 
  Shield, Zap, Activity, Target, AlertCircle, Terminal, Database, Unlock, Lock, ChevronRight, Network, HelpCircle, X, Info, RefreshCw, Download, Eye, Maximize2, RotateCcw
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { List } from 'react-window';
import { AutoSizer } from 'react-virtualized-auto-sizer';
import dynamic from 'next/dynamic';

import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

const ResponsiveGridLayout = dynamic(
  async () => {
    // In RGL 2.x, the v1-style HOCs and components are moved to /legacy
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
}

const isTimeTravel = (log: TelemetryEntry) => {
  if (!log.ingestion_timestamp || !log.timestamp) return false;
  const ingestTime = new Date(log.ingestion_timestamp).getTime();
  const eventTime = new Date(log.timestamp).getTime();
  return (ingestTime - eventTime) > 5000;
};

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
      {/* Visual resize indicator for operator awareness */}
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
  const [isIsolated, setIsIsolated] = useState(false);
  const [showGate, setShowGate] = useState(false);
  const [isHunting, setIsHunting] = useState(false);
  const [showHuntAlert, setShowHuntAlert] = useState(false);
  const [activeView, setActiveView] = useState<'stream' | 'graph'>('stream');
  const [feedMode, setFeedMode] = useState<'tactical' | 'forensic'>('tactical');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
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
    const interval = setInterval(() => {
      if (typingIdx.current < sitrep.length) {
        setDisplayedSitrep(prev => prev + sitrep[typingIdx.current]);
        typingIdx.current++;
      } else {
        clearInterval(interval);
      }
    }, 15);
    return () => clearInterval(interval);
  }, [sitrep]);

  // 2. DATA FETCHING
  const refreshData = async () => {
    try {
      const t = Date.now();
      const [histRes, sitRes, isoRes, healthRes] = await Promise.all([
        fetch(`/telemetry/history?t=${t}`),
        fetch(`/sitrep?t=${t}`),
        fetch(`/isolation/status?t=${t}`),
        fetch(`/system/health?t=${t}`)
      ]);
      if (histRes.ok) {
        const histData = await histRes.json();
        setTelemetry(histData);
        setHubStatus("ONLINE");
      } else {
        throw new Error("EXFIL_BRIDGE_FAILED");
      }
      if (sitRes.ok) {
        const sitData = await sitRes.json();
        setSitrep(sitData.sitrep);
        
        // [SIGNAL SILENCE] Breach-in-the-Storm Auto-Expand
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

  const handleToggleIsolation = async () => {
    await fetch('http://127.0.0.1:8000/isolation/toggle', { method: 'POST' });
    setShowGate(false);
    refreshData();
  };

  const onLayoutChange = (currentLayout: any[], allLayouts: any) => {
    setLayouts(allLayouts);
    localStorage.setItem('aegis-hud-layout', JSON.stringify(allLayouts));
  };

  // 4. DATA PROCESSING (TACTICAL FILTER)
  const isSignalSilenceActive = React.useMemo(() => {
    return clarity.clarity < 50;
  }, [clarity.clarity]);

  const processedTelemetry = React.useMemo(() => {
    if (feedMode === 'forensic') return telemetry;
    
    const results: any[] = [];
    let currentSummary: any = null;

    telemetry.forEach((log) => {
      const isNoiseSummary = log.message?.includes("NOISE DETECTED");
      const isCritical = log.severity === 'hostile' || log.severity === 'critical' || log.severity === 'warning' || isNoiseSummary;
      
      if (isCritical) {
        if (currentSummary) {
          results.push(currentSummary);
          currentSummary = null;
        }
        
        // If it's a noise summary, tag it for special rendering
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
  }, [telemetry, feedMode]);

  // 5. SWARM HEALTH TRACKER
  const activeNodes = React.useMemo(() => {
    const nodes = new Map<string, boolean>();
    const now = Date.now();
    telemetry.forEach(log => {
      if (!log.node_id) return;
      // If ingested within last 60 seconds, node is ONLINE
      const logTime = new Date(log.ingestion_timestamp || log.timestamp).getTime();
      if (now - logTime < 60000) {
        nodes.set(log.node_id, true);
      } else if (!nodes.has(log.node_id)) {
        nodes.set(log.node_id, false);
      }
    });
    return nodes;
  }, [telemetry]);

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
              <button onClick={handleToggleIsolation} className="flex-1 bg-rose-600 text-white text-[10px] font-bold py-2 rounded uppercase tracking-widest hover:bg-rose-500 transition-colors">Execute Lock</button>
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
                   <h4 className="text-cyan-100 font-bold uppercase tracking-widest border-l-2 border-cyan-500 pl-3">Tiled Layout Engine</h4>
                   <p className="text-slate-400 leading-relaxed">
                     The HUD now utilizes a high-density mosaic layout. Click and drag the <span className="text-cyan-500">header handles</span> to rearrange panes. Use the bottom-right corner of any pane to resize. Layouts persist across sessions.
                   </p>
                 </div>
                 <div className="space-y-4">
                   <h4 className="text-rose-400 font-bold uppercase tracking-widest border-l-2 border-rose-500 pl-3">Tactical vs Forensic</h4>
                   <p className="text-slate-400 leading-relaxed">
                     <span className="text-cyan-500">Tactical Mode</span> suppresses nominal telemetry to focus on hostile activity. <span className="text-rose-500">Forensic Mode</span> provides the full, unfiltered virtualized stream for deep-dive investigation.
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
            {isSignalSilenceActive && (
              <div className="flex items-center gap-2 border-l border-slate-800 pl-4">
                <div className="bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded flex items-center gap-1.5 animate-pulse">
                  <Zap className="w-2.5 h-2.5 text-amber-500" />
                  <span className="text-amber-500 font-black text-[9px] tracking-widest">SIGNAL SILENCE ACTIVE</span>
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
          .react-resizable-handle {
            background: none !important;
            z-index: 50 !important;
          }
          .react-resizable-handle-se::after,
          .react-resizable-handle-s::after,
          .react-resizable-handle-e::after {
            content: "";
            position: absolute;
            background: #06b6d4;
            opacity: 0.2;
            transition: opacity 0.2s;
          }
          .react-resizable-handle-se::after {
            right: 2px;
            bottom: 2px;
            width: 10px;
            height: 10px;
            border-right: 2px solid #06b6d4;
            border-bottom: 2px solid #06b6d4;
            background: none;
          }
          .react-resizable-handle-s::after {
            bottom: 0;
            left: 25%;
            width: 50%;
            height: 2px;
          }
          .react-resizable-handle-e::after {
            right: 0;
            top: 25%;
            width: 2px;
            height: 50%;
          }
          .react-resizable-handle:hover::after {
            opacity: 1;
          }
          .layout {
            transition: height 200ms ease;
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
              <div className="p-4 space-y-6 overflow-y-auto h-full">
                <div className="space-y-2">
                  <div className="flex justify-between text-[10px] uppercase tracking-widest font-bold">
                    <span className="text-slate-400">Engine Latency</span>
                    <span className="text-cyan-400">0.42ms</span>
                  </div>
                  <div className="h-1 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-500/50 w-[15%]" />
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-[10px] uppercase tracking-widest font-bold">
                    <span className="text-slate-400">Memory Pressure</span>
                    <span className="text-cyan-400">2.1GB</span>
                  </div>
                  <div className="h-1 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-500/50 w-[45%]" />
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between text-[10px] uppercase tracking-widest font-bold">
                    <span className="text-slate-400">Forensic Clarity</span>
                    <span className={clarity.clarity < 10 ? "text-amber-500" : "text-cyan-400"}>
                      {clarity.clarity.toFixed(1)}%
                    </span>
                  </div>
                  <div className="h-1 bg-slate-950 rounded-full overflow-hidden">
                    <div className={`h-full transition-all duration-500 ${clarity.clarity < 10 ? "bg-amber-500" : "bg-cyan-500/50"}`} style={{ width: `${clarity.clarity}%` }} />
                  </div>
                </div>
                
                {/* SWARM HEALTH GUTTER */}
                <div className="space-y-2 mt-6 border-t border-slate-800 pt-4">
                  <div className="text-[10px] uppercase tracking-widest font-bold text-slate-500 mb-2">Swarm Status</div>
                  {activeNodes.size === 0 && (
                    <div className="text-[10px] text-slate-600 font-mono italic">NO NODES DETECTED</div>
                  )}
                  {Array.from(activeNodes.entries()).map(([node, isOnline]) => (
                    <div key={node} className="flex justify-between items-center text-[10px] uppercase tracking-widest font-bold">
                      <span className="text-slate-400">[{node}]</span>
                      <span className={isOnline ? "text-emerald-500" : "text-rose-500"}>{isOnline ? "ONLINE" : "OFFLINE"}</span>
                    </div>
                  ))}
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
                        p: ({node, ...props}) => <p className="text-xs leading-relaxed text-slate-300 font-sans mb-3" {...props} />,
                        li: ({node, ...props}) => (
                          <li className="flex items-start gap-2 text-[11px] text-slate-400 font-mono mb-1">
                            <span className="text-cyan-500 shrink-0 mt-1">▸</span>
                            <span>{props.children}</span>
                          </li>
                        ),
                        code: ({node, inline, ...props}: any) => (
                          inline 
                            ? <code className="bg-slate-800 px-1 py-0.5 rounded text-[10px] font-mono text-cyan-300" {...props} />
                            : <pre className="bg-black/60 border border-slate-800 p-3 rounded my-4"><code className="text-[10px] font-mono text-amber-200" {...props} /></pre>
                        )
                      }}
                    >
                      {sitrep}
                    </ReactMarkdown>
                    {typingIdx.current < sitrep.length && (
                      <span className="w-2 h-4 bg-cyan-500 inline-block ml-1 animate-pulse" />
                    )}
                  </div>
                </div>
                <div className="p-3 border-t border-slate-800 bg-slate-950/80 flex justify-between items-center text-[8px] uppercase tracking-widest">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-cyan-500 rounded-full animate-pulse" />
                    <span className="text-slate-500">Source: Librarian_AI_Advisor</span>
                  </div>
                  <span className="text-amber-500/80 font-black italic">TACTICAL_READOUT_ACTIVE</span>
                </div>
              </div>
            </TacticalPane>
          </div>

          {/* INTELLIGENCE STREAM / GRAPH */}
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
                      className={`px-2 py-1 text-[8px] font-bold tracking-tighter ${feedMode === 'tactical' ? 'text-cyan-400' : 'text-slate-600 hover:text-slate-400'}`}
                    >
                      TACTICAL
                    </button>
                    <button 
                      onClick={() => setFeedMode('forensic')}
                      className={`px-2 py-1 text-[8px] font-bold tracking-tighter ${feedMode === 'forensic' ? 'text-rose-500' : 'text-slate-600 hover:text-slate-400'}`}
                    >
                      FORENSIC
                    </button>
                  </div>
                </div>

                <div className="flex-1 relative">
                  {activeView === 'stream' ? (
                    <AutoSizer
                      renderProp={({ height, width }) => (
                        <List
                          rowCount={processedTelemetry.length}
                          rowHeight={45}
                          rowProps={{}}
                          className="custom-scrollbar"
                          style={{ height: height || '100%', width: width || '100%' }}
                          rowComponent={({ index, style }) => {
                            const log = processedTelemetry[index];
                            if (log.type === 'summary') {
                              return (
                                <div style={style} className="flex items-center gap-3 px-4 border-b border-slate-800 bg-slate-950/20">
                                  <span className="text-slate-600 text-[9px]">[{log.timestamp}]</span>
                                  <div className="h-px flex-1 bg-slate-800" />
                                  <span className="text-[9px] font-bold text-slate-500 tracking-tighter italic uppercase">
                                    {log.count} Signals Suppressed (UI Level)
                                  </span>
                                  <div className="h-px flex-1 bg-slate-800" />
                                </div>
                              );
                            }
                            
                            if (log.type === 'noise_alert') {
                              return (
                                <div style={style} className="flex items-center gap-3 px-4 border-b border-amber-500/30 bg-amber-900/20">
                                  <span className="text-amber-700 text-[9px] font-mono">[{log.timestamp}]</span>
                                  <Zap className="w-3 h-3 text-amber-500 shrink-0" />
                                  <span className="text-[10px] font-black text-amber-500 tracking-widest uppercase">
                                    {log.message}
                                  </span>
                                  <div className="h-px flex-1 bg-amber-900/20" />
                                  <span className="text-[8px] font-mono text-amber-700/60 italic uppercase">Signal Silence Active</span>
                                </div>
                              );
                            }
                            const tt = isTimeTravel(log);
                            const eventName = log.event || log.message || "UNKNOWN_EVENT";
                            const badgeColor = log.node_id === 'Alpha' ? 'text-slate-400' : (log.node_id === 'Beta' ? 'text-slate-500' : 'text-slate-400');
                            
                            return (
                              <div 
                                style={style} 
                                onClick={() => {
                                  setSelectedNodeId(log.details?.match(/PID: (\d+)/)?.[1] || null);
                                  setActiveView('graph');
                                }}
                                className={`flex items-start gap-3 p-3 border-b text-[10px] cursor-pointer hover:bg-white/5 transition-colors 
                                  ${log.severity === 'hostile' || log.severity === 'critical' ? 'bg-rose-500/10' : ''} 
                                  ${tt ? 'border-dashed border-cyan-500/40 bg-cyan-950/10' : 'border-slate-800'}`}
                              >
                                <span className="text-slate-600 shrink-0 w-16 font-mono">[{log.timestamp}]</span>
                                <span className={`shrink-0 w-16 text-center font-bold tracking-widest uppercase ${badgeColor}`}>
                                  [{log.node_id || 'LOCAL'}]
                                </span>
                                <div className="flex flex-col shrink-0 w-32 gap-1">
                                  <span className={`font-bold tracking-tighter uppercase ${
                                    log.severity === 'hostile' || log.severity === 'critical' ? 'text-rose-500' :
                                    log.severity === 'warning' ? 'text-amber-500' :
                                    log.severity === 'friendly' ? 'text-emerald-500' :
                                    'text-blue-400'
                                  }`}>
                                    {eventName}
                                  </span>
                                  {tt && (
                                    <span className="text-[8px] italic font-bold tracking-widest text-slate-500">
                                      [RECONCILED]
                                    </span>
                                  )}
                                </div>
                                <span className="text-slate-300 truncate flex-1 leading-relaxed">{log.details}</span>
                              </div>
                            );
                          }}
                        />
                      )}
                    />
                  ) : (
                    <AutoSizer
                      renderProp={({ height, width }) => (
                        <ProvenanceGraph 
                          highlightNodeId={selectedNodeId} 
                          width={width} 
                          height={height} 
                        />
                      )}
                    />
                  )}
                </div>
              </div>
            </TacticalPane>
          </div>

          {/* INGESTION MANIFOLD */}
          <div key="manifold">
            <TacticalPane title="Ingestion Manifold" icon={Terminal}>
              <IngestionManifold onComplete={refreshData} />
            </TacticalPane>
          </div>

          {/* OVERWATCH */}
          <div key="overwatch">
            <TacticalPane title="Overwatch" icon={Shield}>
              <div className="p-4 space-y-3 text-[10px] leading-relaxed">
                <p className="text-cyan-500 font-bold">[ACTIVE] Continuous forensic monitoring enabled.</p>
                <p className="text-slate-400">Real-time assets served from Active Intelligence feed.</p>
                <p className="text-slate-400">Kill chain authority authorized.</p>
              </div>
            </TacticalPane>
          </div>

          {/* KILL CHAIN */}
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
                  {isHunting ? 'Hunting...' : 'Deploy Host Hunt'}
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
                  {isIsolated ? 'Restore Network' : 'Isolate Host'}
                </button>
              </div>
            </TacticalPane>
          </div>
        </ResponsiveGridLayout>
      </div>

      {/* 3. STATUS BAR */}
      <footer className="mt-3 flex justify-between items-center text-[9px] uppercase tracking-[0.2em] text-slate-600 font-bold h-8 shrink-0 border-t border-slate-900 pt-2">
        <div className="flex gap-4">
          <span>Latency: 0.42ms // Tunnel: AES-256 GCM</span>
          <span className="text-cyan-950">|</span>
          <span className={hubStatus === "ONLINE" ? "text-cyan-500" : "text-rose-500 animate-pulse"}>
            Hub Status: {hubStatus}
          </span>
        </div>
        <div>Aegis Tactical Manifold V3.5 // MOS PROTOCOL</div>
      </footer>
    </main>
  );
}

export default TacticalHUD;
