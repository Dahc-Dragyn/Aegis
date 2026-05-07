'use client';

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';

interface Node {
  id: string;
  name: string;
  severity: 'hostile' | 'critical' | 'warning' | 'friendly' | 'info';
  timestamp: string;
  type: 'hostile' | 'friendly' | 'unknown';
  node_id?: string;
}

interface Link {
  source: string;
  target: string;
}

interface ProvenanceGraphProps {
  highlightNodeId?: string | null;
  width?: number;
  height?: number;
}

export default function ProvenanceGraph({ highlightNodeId, width: propWidth, height: propHeight }: ProvenanceGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const zoomRef = useRef<any>(null);
  const simulationRef = useRef<any>(null);
  const gRef = useRef<SVGGElement | null>(null);
  const [graphData, setGraphData] = useState<{ nodes: Node[], links: Link[] }>({ nodes: [], links: [] });
  const [selectedNodeData, setSelectedNodeData] = useState<Node | null>(null);
  const [governorActive, setGovernorActive] = useState(false);

  const fetchGraphData = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/telemetry/history');
      if (!response.ok) return;
      const logs = await response.json();
      
      const nodes: Node[] = [];
      const links: Link[] = [];
      const nodeSet = new Set<string>();

      // --- SNR HEURISTIC: Detect Signal Storm ---
      const noiseDetected = logs.some((l: any) => (l.message || "").includes("NOISE DETECTED"));
      const isHighVolume = logs.length > 200 || noiseDetected;
      setGovernorActive(isHighVolume);

      const addNode = (id: string, name: string, severity: any, timestamp: string, ppid: string | null, node_id?: string) => {
        if (!id || id === "0") return;
        
        const sevStr = (severity || 'info').toLowerCase();
        const type: 'hostile' | 'friendly' | 'unknown' = 
          (sevStr === 'hostile' || sevStr === 'critical') ? 'hostile' :
          (sevStr === 'friendly') ? 'friendly' : 'unknown';

        // GOVERNOR: Discard neutral/friendly nodes in High Volume mode
        if (isHighVolume && type !== 'hostile' && sevStr !== 'warning') return;

        if (!nodeSet.has(id)) {
          nodes.push({ id, name, severity: severity || 'info', timestamp, type, node_id: node_id || 'LOCAL' });
          nodeSet.add(id);
        }

        if (ppid && ppid !== "0" && ppid !== "1000") {
          // Only add links if both nodes exist (governor might have dropped parent)
          links.push({ source: ppid, target: id });
          if (!nodeSet.has(ppid) && (!isHighVolume || type !== 'unknown')) {
             // We don't add "Unknown Parent" in high volume mode if it's likely to be noise
             // but if the child is hostile, we might want the link?
             // Actually, for simplicity, we just link what we have.
          }
        }
      };

      logs.forEach((log: any) => {
        // Structured JSON Parser (Priority)
        const eventObj = log.Event || log.event;
        
        if (eventObj && typeof eventObj === 'object') {
          const system = eventObj.System;
          const data = eventObj.EventData;
          if (system && data) {
            const eventId = system.EventID;
            if (eventId === 4688) {
              // Windows Security: Process Creation
              const pid = parseInt(data.NewProcessId, 16).toString();
              const ppid = parseInt(data.ProcessId, 16).toString();
              const name = data.NewProcessName?.split('\\').pop() || "Unknown";
              addNode(pid, name, log.severity, log.timestamp, ppid, log.node_id);
            } else if (eventId === 1) {
              // Sysmon: Process Creation
              const pid = data.ProcessId?.toString();
              const ppid = data.ParentProcessId?.toString();
              const name = data.Image?.split('\\').pop() || "Unknown";
              addNode(pid, name, log.severity, log.timestamp, ppid, log.node_id);
            }
          }
        } else if (typeof eventObj === 'string') {
          // Legacy String Parser
          const match = eventObj.match(/Process Created: (.*?) \(PID: (\d+), Parent: (\d+)\)/);
          if (match) {
            const [_, name, pid, ppid] = match;
            addNode(pid, name, log.severity, log.timestamp, ppid, log.node_id);
          }
        }
      });

      // --- FRONTEND GOVERNOR: Filter dead links and limit ---
      const activeIds = new Set(nodes.map(n => n.id));
      const validLinks = links.filter(l => activeIds.has(l.source as string) && activeIds.has(l.target as string));

      setGraphData({ nodes: nodes.slice(0, 500), links: validLinks.slice(0, 1000) });
    } catch (e) {
      console.error("[HUD] GRAPH_FETCH_ERROR:", e);
    }
  };

  useEffect(() => {
    fetchGraphData();
    const poll = setInterval(fetchGraphData, 5000);
    return () => clearInterval(poll);
  }, []);

  useEffect(() => {
    if (!svgRef.current || graphData.nodes.length === 0) return;

    const width = propWidth || svgRef.current.clientWidth || 800;
    const height = propHeight || svgRef.current.clientHeight || 600;
    
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    if (simulationRef.current) {
      simulationRef.current.stop();
    }

    // --- TUNED D3 PHYSICS: Faster convergence for dense data ---
    const isGovernorEngaged = graphData.nodes.length > 200;
    
    const simulation = d3.forceSimulation(graphData.nodes as any)
      .force("link", d3.forceLink(graphData.links).id((d: any) => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(isGovernorEngaged ? -50 : -300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(40))
      .alphaDecay(isGovernorEngaged ? 0.08 : 0.05)
      .velocityDecay(0.4);

    const g = svg.append("g");
    gRef.current = g.node();

    // MIL-SPEC Marker (Arrowhead)
    svg.append("defs").append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "-0 -5 10 10")
      .attr("refX", 25)
      .attr("refY", 0)
      .attr("orient", "auto")
      .attr("markerWidth", 5)
      .attr("markerHeight", 5)
      .append("svg:path")
      .attr("d", "M 0,-5 L 10 ,0 L 0,5")
      .attr("fill", "#475569")
      .style("stroke", "none");

    const link = g.append("g")
      .attr("stroke", "#1e293b")
      .attr("stroke-opacity", 0.8)
      .selectAll("line")
      .data(graphData.links)
      .join("line")
      .attr("stroke-width", 1)
      .attr("marker-end", "url(#arrowhead)");

    const node = g.append("g")
      .selectAll("g")
      .data(graphData.nodes)
      .join("g")
      .attr("id", (d: any) => `node-${d.id}`)
      .call(d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended) as any);

    // MATTE SYMBOLOGY (MIL-STD-2525D)
    node.each(function(d: any) {
      const el = d3.select(this);
      if (d.type === 'hostile') {
        // Red Diamond
        el.append("path")
          .attr("d", "M 0 -10 L 10 0 L 0 10 L -10 0 Z")
          .attr("fill", "#FF0000")
          .attr("stroke", "#7f0000")
          .attr("stroke-width", 2);
      } else if (d.type === 'friendly') {
        // Green Circle
        el.append("circle")
          .attr("r", 9)
          .attr("fill", "#00FF00")
          .attr("stroke", "#007f00")
          .attr("stroke-width", 2);
      } else {
        // Yellow Square
        el.append("rect")
          .attr("x", -8)
          .attr("y", -8)
          .attr("width", 16)
          .attr("height", 16)
          .attr("fill", "#FFFF00")
          .attr("stroke", "#7f7f00")
          .attr("stroke-width", 2);
      }
    });

    // Highlight Ring (Matte)
    node.append("circle")
      .attr("r", 15)
      .attr("fill", "none")
      .attr("stroke", "#22d3ee")
      .attr("stroke-width", 2)
      .style("opacity", (d: any) => d.id === highlightNodeId ? 1 : 0);

    node.append("text")
      .attr("dx", 14)
      .attr("dy", 4)
      .text((d: any) => d.name)
      .attr("fill", "#94a3b8")
      .style("font-family", "monospace")
      .style("font-size", "9px")
      .style("font-weight", "bold")
      .style("pointer-events", "none");

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    const zoom = d3.zoom()
      .extent([[0, 0], [width, height]])
      .scaleExtent([0.1, 8])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    zoomRef.current = zoom;
    svg.call(zoom as any);

    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
      setSelectedNodeData(d);
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    simulationRef.current = simulation;

    return () => {
      simulation.stop();
    };
  }, [graphData, highlightNodeId, propWidth, propHeight]);

  useEffect(() => {
    if (!highlightNodeId || !svgRef.current || !zoomRef.current || graphData.nodes.length === 0) return;

    const node = graphData.nodes.find(n => n.id === highlightNodeId);
    if (node) {
      const width = propWidth || svgRef.current.clientWidth;
      const height = propHeight || svgRef.current.clientHeight;

      d3.select(svgRef.current).transition().duration(750).call(
        zoomRef.current.transform,
        d3.zoomIdentity.translate(width / 2, height / 2).scale(2).translate(-(node as any).x, -(node as any).y)
      );
    }
  }, [highlightNodeId, propWidth, propHeight]);

  return (
    <div className="w-full h-full bg-[#121212] relative cursor-crosshair overflow-hidden border border-slate-800">
      <svg ref={svgRef} className="w-full h-full" />
      <div className="absolute bottom-2 left-2 flex gap-3 bg-black/60 p-2 border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center gap-1 text-[9px] uppercase font-bold text-slate-400">
              <div className="w-2.5 h-2.5 rounded-full bg-[#00FF00] border border-[#007f00]" /> Friendly
          </div>
          <div className="flex items-center gap-1 text-[9px] uppercase font-bold text-slate-400">
              <div className="w-2.5 h-2.5 bg-[#FF0000] border border-[#7f0000] rotate-45" /> Hostile
          </div>
          <div className="flex items-center gap-1 text-[9px] uppercase font-bold text-slate-400">
              <div className="w-2.5 h-2.5 bg-[#FFFF00] border border-[#7f7f00]" /> Unknown
          </div>
      </div>
      <div className="absolute top-2 right-2 flex flex-col items-end gap-1">
        <div className="text-[8px] font-mono text-slate-600 uppercase tracking-tighter">
          D3_NODE_GOVERNOR: {graphData.nodes.length}/500 | FPS: 60
        </div>
        {governorActive && (
          <div className="bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 animate-pulse">
            <span className="text-amber-500 text-[8px] font-black tracking-widest uppercase">
              GOVERNOR ACTIVE: SIGNAL PRIORITY MODE
            </span>
          </div>
        )}
      </div>
      
      {/* ASSET ORIGIN SIDE PANEL */}
      {selectedNodeData && (
        <div className="absolute top-2 left-2 w-56 bg-slate-950/90 border border-cyan-500/30 p-4 shadow-xl backdrop-blur-md">
          <h3 className="text-cyan-400 font-black text-xs uppercase tracking-[0.2em] mb-3 border-b border-cyan-500/30 pb-1">Asset Origin</h3>
          <div className="space-y-2 font-mono text-[10px]">
            <div className="flex justify-between border-b border-slate-800 pb-1">
              <span className="text-slate-500">Node ID:</span>
              <span className={`font-bold uppercase ${selectedNodeData.node_id === 'Alpha' ? 'text-slate-400' : 'text-slate-500'}`}>[{selectedNodeData.node_id}]</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-1">
              <span className="text-slate-500">Process:</span>
              <span className="text-slate-300 truncate max-w-[100px] text-right" title={selectedNodeData.name}>{selectedNodeData.name}</span>
            </div>
            <div className="flex justify-between border-b border-slate-800 pb-1">
              <span className="text-slate-500">Time:</span>
              <span className="text-slate-300 truncate max-w-[100px] text-right">{selectedNodeData.timestamp}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
