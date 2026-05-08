'use client';

import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { FileText, Download, ShieldCheck, Box, FileSearch, Eye, X, AlertTriangle, Zap } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface Artifact {
  name: string;
  type: 'NIST' | 'OSCAL' | 'BRIEF' | 'LOG' | 'TRIAGE' | 'LEDGER';
  path: string;
  timestamp?: string;
}

export default function ArtifactVault() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null);
  const [artifactContent, setArtifactContent] = useState<string | null>(null);
  const [isViewing, setIsViewing] = useState(false);

  useEffect(() => {
    const fetchArtifacts = async () => {
      try {
        const response = await fetch(`/artifacts?t=${Date.now()}`);
        if (response.ok) {
          const data = await response.json();
          setArtifacts(data);
        }
      } catch (error) {
        console.error('[HUD] FAILED TO FETCH ASSETS', error);
      }
    };

    fetchArtifacts();
    const interval = setInterval(fetchArtifacts, 5000); // Faster refresh for active ops
    return () => clearInterval(interval);
  }, []);

  const handleClose = (e?: React.MouseEvent | KeyboardEvent) => {
    if (e && 'stopPropagation' in e) e.stopPropagation();
    setIsViewing(false);
    setSelectedArtifact(null);
  };

  useEffect(() => {
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') handleClose(); };
    if (isViewing) window.addEventListener('keydown', onEsc);
    return () => window.removeEventListener('keydown', onEsc);
  }, [isViewing]);

  const handleView = async (artifact: Artifact) => {
    setSelectedArtifact(artifact);
    setIsViewing(true);
    setArtifactContent("### STREAMING REAL-TIME INTELLIGENCE...");
    try {
      const response = await fetch(`${artifact.path}?t=${Date.now()}`);
      const data = await response.json();
      setArtifactContent(data.content || "ERROR: NO CONTENT RETURNED.");
    } catch (error) {
      setArtifactContent("# SYSTEM_ERROR\n\nLINK_TO_COMMAND_HUB_INTERRUPTED.");
    }
  };

  return (
    <div className="flex-1 relative flex flex-col min-h-0 overflow-hidden">
      <div className="flex-1 p-3 overflow-y-auto custom-scrollbar bg-slate-900/20">
        <div className="space-y-2">
          {artifacts.length === 0 && (
            <div className="text-center py-12 opacity-20 uppercase tracking-[0.2em] text-[10px] border border-dashed border-slate-800 rounded">
              Feed Standby // Waiting for Signal
            </div>
          )}
          {artifacts.map((artifact, i) => (
            <div 
              key={i} 
              className={`border rounded p-2 flex items-center justify-between group transition-all
                ${artifact.type === 'BRIEF' ? 'bg-amber-950/20 border-amber-500/30' : 'bg-slate-900/40 border-slate-800/50 hover:border-cyan-500/30'}
                ${i === 0 ? 'ring-1 ring-cyan-500/20' : ''}
              `}
            >
              <div className="flex items-center gap-2 min-w-0">
                <div className={`p-1.5 rounded bg-slate-950 border ${
                  artifact.type === 'BRIEF' ? 'border-amber-500 text-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.2)]' :
                  artifact.type === 'NIST' ? 'border-emerald-500/50 text-emerald-500' :
                  artifact.type === 'OSCAL' ? 'border-cyan-500/50 text-cyan-500' : 
                  artifact.type === 'LEDGER' ? 'border-fuchsia-500/50 text-fuchsia-500' : 'border-slate-700 text-slate-400'
                }`}>
                  {artifact.type === 'BRIEF' ? <Zap className="w-3.5 h-3.5" /> :
                   artifact.type === 'NIST' ? <ShieldCheck className="w-3.5 h-3.5" /> :
                   artifact.type === 'LEDGER' ? <FileText className="w-3.5 h-3.5" /> :
                   <Box className="w-3.5 h-3.5" />}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`text-[9px] font-bold uppercase tracking-widest leading-none 
                      ${artifact.type === 'BRIEF' ? 'text-amber-500' : 'text-slate-500'}
                    `}>
                      {artifact.type === 'BRIEF' ? 'ACTIVE MISSION BRIEF' : artifact.type}
                    </div>
                    {i === 0 && (
                      <span className="text-[8px] px-1 bg-cyan-600 text-white font-black animate-pulse rounded">LATEST_SIGNAL</span>
                    )}
                  </div>
                  <div className={`text-[10px] font-mono truncate w-48 leading-none 
                    ${artifact.type === 'BRIEF' ? 'text-amber-200 font-bold' : 'text-slate-300'}
                  `}>
                    {artifact.name}
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-1 shrink-0">
                <button 
                  onClick={() => handleView(artifact)}
                  className={`p-1.5 rounded transition-colors ${
                    artifact.type === 'BRIEF' ? 'bg-amber-500 text-black hover:bg-amber-400' : 'hover:bg-slate-800 text-cyan-400'
                  }`}
                  title="View Intelligence"
                >
                  <Eye className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* THEATER MODE PORTAL: ESCAPES THE GRID TRANSFORM CONTEXT */}
      {isViewing && typeof document !== 'undefined' && createPortal(
        <div className="fixed inset-0 z-[10000] flex items-center justify-center p-4 md:p-8">
          {/* MATTE BACKDROP (NO BLUR) */}
          <div 
            className="absolute inset-0 bg-slate-950/95 animate-in fade-in duration-300 cursor-zoom-out"
            onClick={handleClose}
          />
          
          {/* THEATER CONTAINER */}
          <div className="relative w-full h-full max-w-[95vw] max-h-[95vh] bg-slate-900 border border-slate-800 rounded-lg shadow-[0_0_100px_rgba(0,0,0,0.8)] flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
            
            {/* TACTICAL HEADER (FIXED) */}
            <div className="h-16 px-8 flex items-center justify-between border-b border-slate-800 bg-slate-950/80 backdrop-brightness-125 z-10 shrink-0">
              <div className="flex items-center gap-6">
                <div className={`p-2 rounded ${selectedArtifact?.type === 'BRIEF' ? 'bg-amber-500' : 'bg-cyan-600'}`}>
                  {selectedArtifact?.type === 'BRIEF' ? <Zap className="w-6 h-6 text-black" /> : <FileSearch className="w-6 h-6 text-black" />}
                </div>
                <div className="min-w-0">
                  <h3 className="text-sm font-black uppercase tracking-[0.4em] text-white truncate max-w-xl">
                    {selectedArtifact?.name}
                  </h3>
                  <div className="flex items-center gap-3 mt-1 text-[10px]">
                    <span className="px-2 py-0.5 bg-slate-800 text-slate-400 font-bold rounded uppercase tracking-widest border border-slate-700">
                      FORENSIC_ASSET // {selectedArtifact?.type}
                    </span>
                    <span className="text-cyan-500/50 font-mono tracking-tighter">HASH_VERIFIED: OK</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                {selectedArtifact && (
                  <a 
                    href={`/artifacts/view/${selectedArtifact.name}`}
                    target="_blank"
                    className="px-6 py-2.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-black uppercase tracking-[0.2em] rounded border border-slate-700 transition-all flex items-center gap-2 group"
                  >
                    <Download className="w-4 h-4 group-hover:translate-y-0.5 transition-transform" />
                    Download for Audit
                  </a>
                )}
                <button 
                  onClick={handleClose} 
                  className="px-6 py-2.5 bg-rose-600/10 hover:bg-rose-600 text-rose-500 hover:text-white rounded border border-rose-500/30 transition-all flex items-center gap-2 group shadow-lg"
                >
                  <span className="text-xs font-black uppercase tracking-[0.2em]">Terminate View</span>
                  <X className="w-5 h-5 group-hover:rotate-90 transition-transform" />
                </button>
              </div>
            </div>

            {/* MAIN INDEPENDENT SCROLL AREA */}
            <div className="flex-1 overflow-y-auto custom-scrollbar bg-slate-900/40 p-8 md:p-16 lg:p-24 selection:bg-cyan-500/30">
              {/* TYPOGRAPHIC COLUMN (max-w-4xl) */}
              <div className="max-w-4xl mx-auto">
                <article className="tactical-markdown-container prose prose-invert prose-slate max-w-none 
                  prose-headings:uppercase prose-headings:tracking-tighter prose-headings:font-black
                  prose-h1:text-5xl prose-h1:border-b-2 prose-h1:border-cyan-500/40 prose-h1:pb-6 prose-h1:mb-12
                  prose-h2:text-2xl prose-h2:mt-16 prose-h2:mb-8 prose-h2:border-l-4 prose-h2:border-cyan-500 prose-h2:pl-6 prose-h2:bg-cyan-950/20 prose-h2:py-3
                  prose-h3:text-lg prose-h3:text-amber-500 prose-h3:mt-10 prose-h3:mb-4
                  prose-p:text-lg prose-p:leading-relaxed prose-p:text-slate-300 prose-p:mb-8
                  prose-li:text-slate-300 prose-li:mb-2
                  prose-strong:text-white prose-strong:font-bold
                  prose-code:text-amber-400 prose-code:bg-amber-950/20 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded
                  prose-pre:bg-black/50 prose-pre:border prose-pre:border-slate-800 prose-pre:shadow-inner
                  prose-table:border prose-table:border-slate-800 prose-table:rounded-lg
                  prose-th:bg-slate-800 prose-th:text-cyan-500 prose-th:p-4 prose-th:uppercase prose-th:tracking-widest
                  prose-td:p-4 prose-td:border-t prose-td:border-slate-800/50
                ">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {artifactContent || ''}
                  </ReactMarkdown>
                </article>

                {/* END OF INTELLIGENCE MARKER */}
                <div className="mt-32 py-16 border-t border-slate-800/50 flex flex-col items-center">
                  <ShieldCheck className="w-12 h-12 text-slate-800 mb-6" />
                  <div className="text-[10px] font-black uppercase tracking-[1em] text-slate-600 animate-pulse text-center">
                    // END OF DATA STREAM // AEGIS_V4 //
                  </div>
                </div>
              </div>
            </div>

            {/* MODAL FOOTER BAR */}
            <div className="h-10 px-8 bg-slate-950 border-t border-slate-800 flex items-center justify-between shrink-0">
              <div className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-6">
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  Link Status: Nominal
                </span>
                <span>Payload: NIST_800-53R5_COMPLIANT</span>
                <span>Read Mode: Focus_Theater</span>
              </div>
              <div className="flex gap-1.5">
                {[1,2,3,4,5,6,7,8].map(i => <div key={i} className="w-1 h-3 bg-slate-800" />)}
              </div>
            </div>

          </div>
        </div>,
        document.body
      )}
    </div>
  );
}
