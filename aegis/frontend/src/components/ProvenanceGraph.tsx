'use client';

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Activity, Target, Network } from 'lucide-react';

interface Node {
  id: string;
  name: string;
  severity: 'hostile' | 'critical' | 'warning' | 'friendly' | 'info';
  timestamp: string;
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
  const gRef = useRef<SVGGElement | null>(null);
  const [graphData, setGraphData] = useState<{ nodes: Node[], links: Link[] }>({ nodes: [], links: [] });

  const fetchGraphData = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/telemetry/history');
      if (!response.ok) return;
      const logs = await response.json();
      
      const nodes: Node[] = [];
      const links: Link[] = [];
      const nodeSet = new Set<string>();

      logs.forEach((log: any) => {
        const match = log.event.match(/Process Created: (.*?) \(PID: (\d+), Parent: (\d+)\)/);
        if (match) {
          const [_, name, pid, ppid] = match;
          const nodeId = pid;
          const parentId = ppid;

          if (!nodeSet.has(nodeId)) {
            nodes.push({ id: nodeId, name, severity: log.severity, timestamp: log.timestamp });
            nodeSet.add(nodeId);
          }
          
          if (parentId && parentId !== "0" && parentId !== "1000") {
            links.push({ source: parentId, target: nodeId });
            if (!nodeSet.has(parentId)) {
                nodes.push({ id: parentId, name: "Unknown Parent", severity: 'info', timestamp: '' });
                nodeSet.add(parentId);
            }
          }
        }
      });

      setGraphData({ nodes, links });
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

    const simulation = d3.forceSimulation(graphData.nodes as any)
      .force("link", d3.forceLink(graphData.links).id((d: any) => d.id).distance(60))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30));

    const g = svg.append("g");
    gRef.current = g.node();

    svg.append("defs").append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "-0 -5 10 10")
      .attr("refX", 20)
      .attr("refY", 0)
      .attr("orient", "auto")
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("xoverflow", "visible")
      .append("svg:path")
      .attr("d", "M 0,-5 L 10 ,0 L 0,5")
      .attr("fill", "#334155")
      .style("stroke", "none");

    const link = g.append("g")
      .attr("stroke", "#334155")
      .attr("stroke-opacity", 0.6)
      .selectAll("line")
      .data(graphData.links)
      .join("line")
      .attr("stroke-width", 1.5)
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

    node.append("circle")
      .attr("r", 8)
      .attr("fill", (d: any) => 
        d.severity === 'hostile' || d.severity === 'critical' ? '#f43f5e' : 
        d.severity === 'warning' ? '#f59e0b' : 
        d.severity === 'friendly' ? '#10b981' : '#0ea5e9'
      )
      .attr("stroke", "#020617")
      .attr("stroke-width", 2);

    node.append("circle")
      .attr("r", 14)
      .attr("fill", "none")
      .attr("stroke", "#22d3ee")
      .attr("stroke-width", 2)
      .attr("class", "highlight-ring")
      .style("opacity", (d: any) => d.id === highlightNodeId ? 1 : 0);

    node.append("text")
      .attr("dx", 12)
      .attr("dy", 4)
      .text((d: any) => d.name)
      .attr("fill", "#94a3b8")
      .style("font-size", "8px")
      .style("font-weight", "bold")
      .style("text-transform", "uppercase")
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
      .scaleExtent([0.5, 5])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    zoomRef.current = zoom;
    svg.call(zoom as any);

    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
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
    <div className="w-full h-full bg-black/40 relative cursor-crosshair overflow-hidden">
      <svg ref={svgRef} className="w-full h-full" />
      <div className="absolute bottom-2 left-2 flex gap-2">
          <div className="flex items-center gap-1 text-[8px] uppercase font-bold text-slate-500">
              <div className="w-2 h-2 rounded-full bg-emerald-500" /> Friendly
          </div>
          <div className="flex items-center gap-1 text-[8px] uppercase font-bold text-slate-500">
              <div className="w-2 h-2 rounded-full bg-rose-500" /> Hostile
          </div>
      </div>
    </div>
  );
}
