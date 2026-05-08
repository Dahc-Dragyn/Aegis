'use client';

import React, { useState } from 'react';
import { Upload, ShieldAlert, Terminal, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function IngestionManifold({ onComplete }: { onComplete?: () => void }) {
  const [isUploading, setIsUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [status, setStatus] = useState<'idle' | 'scanning' | 'complete' | 'error'>('idle');
  const [result, setResult] = useState<string | null>(null);

  const processExfil = async (files: FileList | File[]) => {
    if (files.length === 0) return;

    setIsUploading(true);
    setStatus('scanning');
    setResult("INITIATING MULTI-STREAM INGEST...");

    try {
      const formData = new FormData();
      Array.from(files).forEach(file => {
        formData.append('files', file);
      });

      // DEBUG: LOG FORM DATA KEYS
      for (let pair of (formData as any).entries()) {
        console.log(`[HUD] BRIDGE_DATA_PAYLOAD: ${pair[0]} -> ${pair[1].name}`);
      }

      console.log(`[HUD] INITIATING EXFIL BRIDGE: ${files.length} ARTIFACTS`);
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout for large logs

      const response = await fetch(`/exfil/upload?t=${Date.now()}`, {
        method: 'POST',
        body: formData,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const data = await response.json();
        const ingestedCount = data.ingested?.length || 0;
        setStatus('complete');
        setResult(`EXFIL SUCCESS: ${ingestedCount} ASSETS VAULTED.`);
        
        // TRIGGER GLOBAL REFRESH
        if (onComplete) onComplete();
      } else {
        const errorData = await response.json().catch(() => ({}));
        const errorMsg = typeof errorData.detail === 'string' 
          ? errorData.detail 
          : JSON.stringify(errorData.detail) || "EXFIL_BRIDGE_FAILED";
        throw new Error(errorMsg);
      }
    } catch (error: any) {
      setStatus('error');
      console.error('[HUD] EXFIL FAILED', error);
      setResult(error.message || "ERROR: BRIDGE COLLAPSE.");
    } finally {
      setIsUploading(false);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    processExfil(e.dataTransfer.files);
  };

  return (
    <div className="pane shrink-0">
      <div className="pane-header">
        <span>Forensic Ingestion</span>
        <Upload className="w-3 h-3 text-cyan-400" />
      </div>
      
      <div className="p-3">
        <div 
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={onDrop}
          className={`border-2 border-dashed rounded p-6 flex flex-col items-center justify-center gap-3 transition-all
            ${isDragging ? 'border-emerald-500 bg-slate-800/50' : 
              status === 'scanning' ? 'border-amber-500/50 bg-amber-500/5' : 
              status === 'error' ? 'border-rose-500/50 bg-rose-500/5' :
              'border-slate-700 bg-slate-950/50'}
          `}
        >
          {status === 'idle' && (
            <>
              <ShieldAlert className={`w-8 h-8 transition-colors ${isDragging ? 'text-emerald-500' : 'text-slate-700'}`} />
              <div className="text-center">
                <p className="text-[10px] uppercase tracking-[0.2em] font-black text-slate-400 leading-tight">Forensic Bridge</p>
                <p className="text-[8px] font-mono text-slate-500 mt-1">Drop PCAP, EVTX, LOG, or JSON Artifacts</p>
              </div>
              <label className="cursor-pointer bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-300 text-[9px] font-bold px-4 py-2 rounded uppercase tracking-widest transition-all mt-2">
                Manual Ingest
                <input type="file" multiple className="hidden" onChange={(e) => e.target.files && processExfil(e.target.files)} />
              </label>
            </>
          )}

          {status === 'scanning' && (
            <>
              <Terminal className="w-8 h-8 text-amber-500 animate-pulse" />
              <p className="text-amber-500 font-mono text-[9px] uppercase tracking-widest">Decompressing Ledger...</p>
            </>
          )}

          {status === 'complete' && (
            <>
              <CheckCircle2 className="w-8 h-8 text-emerald-500" />
              <div className="text-center">
                <p className="text-emerald-500 font-bold text-[10px] uppercase tracking-widest leading-tight">Exfil Complete</p>
                <p className="text-slate-500 font-mono text-[8px] mt-1">{result}</p>
              </div>
              <button onClick={() => setStatus('idle')} className="mt-2 text-cyan-500 hover:text-cyan-400 text-[9px] font-mono uppercase tracking-widest underline underline-offset-4">
                [ Reset Manifold ]
              </button>
            </>
          )}

          {status === 'error' && (
            <>
              <AlertTriangle className="w-8 h-8 text-rose-500" />
              <div className="text-center">
                <p className="text-rose-500 font-bold text-[10px] uppercase tracking-widest">Bridge Failure</p>
                <p className="text-slate-500 font-mono text-[8px] mt-1">{result}</p>
              </div>
              <button onClick={() => setStatus('idle')} className="mt-2 text-rose-500 hover:text-rose-400 text-[9px] font-mono uppercase tracking-widest">
                [ Retry ]
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
