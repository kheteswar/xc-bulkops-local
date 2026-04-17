// ═══════════════════════════════════════════════════════════════════════════
// RELATIONSHIP GRAPH - Adaptive clustered layout with focus mode
// Click a node → connected objects pop out, grouped by type in vertical columns
// Pinch-to-zoom only (two-finger scroll pans instead)
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { ZoomIn, ZoomOut, Maximize2, Minimize2, Info, ArrowLeft } from 'lucide-react';
import type { RelationshipGraphData, GraphNode, GraphEdge, FetchedObject } from '../../services/config-dump';
import { getTypeColor, OBJECT_TYPES } from '../../services/config-dump';

// ── Layout types ─────────────────────────────────────────────────

interface PositionedNode {
  node: GraphNode;
  x: number;
  y: number;
}

interface Cluster {
  type: string;
  label: string;
  color: string;
  x: number;
  y: number;
  w: number;
  h: number;
  nodeW: number;
  cx: number;
  cy: number;
  nodes: PositionedNode[];
}

interface FocusGroup {
  type: string;
  label: string;
  color: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

interface FocusMeta {
  cx: number;
  cy: number;
  nodeIds: Set<string>;
  groups: FocusGroup[];
}

// ── Sizing constants ──────────────────────────────────────────────

const MIN_NODE_W = 130;
const MAX_NODE_W = 240;
const FOCUS_NODE_W = 200;
const NODE_H = 28;
const NODE_GAP = 10;
const CHAR_WIDTH = 6.2;
const CLUSTER_PAD_X = 18;
const CLUSTER_PAD_TOP = 40;
const CLUSTER_PAD_BOT = 18;
const CLUSTER_GAP = 40;
const TOP_MARGIN = 24;
const FOCUS_GROUP_GAP = 32;

// ── Compute adaptive clustered layout ─────────────────────────────

function computeClusteredLayout(
  nodes: GraphNode[],
  _edges: GraphEdge[],
  canvasW: number,
  _canvasH: number,
): { clusters: Cluster[]; positions: Map<string, { x: number; y: number }>; totalW: number; totalH: number } {
  const groups = new Map<string, GraphNode[]>();
  for (const node of nodes) {
    if (!groups.has(node.type)) groups.set(node.type, []);
    groups.get(node.type)!.push(node);
  }

  const typeKeys = Array.from(groups.keys());
  if (typeKeys.length === 0) return { clusters: [], positions: new Map(), totalW: 0, totalH: 0 };

  const specs = typeKeys.map(type => {
    const group = groups.get(type)!;
    const count = group.length;
    const longestName = Math.max(...group.map(n => n.name.length));
    const textNeeded = longestName * CHAR_WIDTH + 36;
    const nodeW = Math.min(MAX_NODE_W, Math.max(MIN_NODE_W, Math.ceil(textNeeded)));
    // Adaptive: compute max rows that fit in canvas height, use enough columns to avoid scrolling
    const availableH = _canvasH - TOP_MARGIN - CLUSTER_GAP;
    const maxRowsForHeight = Math.max(1, Math.floor((availableH - CLUSTER_PAD_TOP - CLUSTER_PAD_BOT + NODE_GAP) / (NODE_H + NODE_GAP)));
    const heightCols = Math.max(1, Math.ceil(count / maxRowsForHeight));
    const idealCols = Math.max(heightCols, Math.ceil(Math.sqrt(count)));
    const cols = Math.min(idealCols, count);
    const rows = Math.ceil(count / cols);
    const w = cols * nodeW + (cols - 1) * NODE_GAP + CLUSTER_PAD_X * 2;
    const h = CLUSTER_PAD_TOP + rows * NODE_H + (rows - 1) * NODE_GAP + CLUSTER_PAD_BOT;
    const color = getTypeColor(type);
    const typeDef = OBJECT_TYPES.find(t => t.id === type);
    const label = typeDef ? typeDef.label : type.replace(/_/g, ' ');
    return { type, group, nodeW, cols, rows, w, h, color, label };
  });

  const clusters: Cluster[] = [];
  const positions = new Map<string, { x: number; y: number }>();
  let curX = CLUSTER_GAP;
  let curY = TOP_MARGIN;
  let rowMaxH = 0;

  for (const spec of specs) {
    if (curX + spec.w + CLUSTER_GAP > canvasW && curX > CLUSTER_GAP) {
      curX = CLUSTER_GAP;
      curY += rowMaxH + CLUSTER_GAP;
      rowMaxH = 0;
    }
    const clusterX = curX;
    const clusterY = curY;
    const positionedNodes: PositionedNode[] = [];
    for (let j = 0; j < spec.group.length; j++) {
      const col = j % spec.cols;
      const row = Math.floor(j / spec.cols);
      const nx = clusterX + CLUSTER_PAD_X + col * (spec.nodeW + NODE_GAP) + spec.nodeW / 2;
      const ny = clusterY + CLUSTER_PAD_TOP + row * (NODE_H + NODE_GAP) + NODE_H / 2;
      positions.set(spec.group[j].id, { x: nx, y: ny });
      positionedNodes.push({ node: spec.group[j], x: nx, y: ny });
    }
    clusters.push({
      type: spec.type, label: spec.label, color: spec.color,
      x: clusterX, y: clusterY, w: spec.w, h: spec.h, nodeW: spec.nodeW,
      cx: clusterX + spec.w / 2, cy: clusterY + spec.h / 2,
      nodes: positionedNodes,
    });
    curX += spec.w + CLUSTER_GAP;
    rowMaxH = Math.max(rowMaxH, spec.h);
  }

  const totalW = clusters.length > 0 ? Math.max(...clusters.map(c => c.x + c.w)) + CLUSTER_GAP : 0;
  const totalH = curY + rowMaxH + CLUSTER_GAP;
  return { clusters, positions, totalW, totalH };
}

// ── Component ────────────────────────────────────────────────────

interface RelationshipGraphProps {
  data: RelationshipGraphData;
  results: FetchedObject[];
  onSelectObject?: (obj: FetchedObject) => void;
}

export function RelationshipGraph({ data, results, onSelectObject }: RelationshipGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const wrapperRef = useRef<HTMLDivElement>(null);

  // Fullscreen
  const [isFullscreen, setIsFullscreen] = useState(false);

  const toggleFullscreen = useCallback(() => {
    if (!wrapperRef.current) return;
    if (!document.fullscreenElement) {
      wrapperRef.current.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  }, []);

  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  // Core state
  const [dimensions, setDimensions] = useState({ width: 1200, height: 700 });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState<{ nodeId: string; startX: number; startY: number } | null>(null);
  const [panning, setPanning] = useState<{ startX: number; startY: number; panX: number; panY: number } | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  // Focus mode: directly moves nodes in nodePositions, saves originals to restore
  const [focusMeta, setFocusMeta] = useState<FocusMeta | null>(null);
  const savedPositionsRef = useRef<Map<string, { x: number; y: number }> | null>(null);

  // Refs to avoid stale closures
  const zoomRef = useRef(zoom);
  const panRef = useRef(pan);
  useEffect(() => { zoomRef.current = zoom; }, [zoom]);
  useEffect(() => { panRef.current = pan; }, [pan]);

  // ── Layout computation ──────────────────────────────────────────

  const { clusters, initialPositions, contentWidth, contentHeight } = useMemo(() => {
    if (data.nodes.length === 0) return { clusters: [] as Cluster[], initialPositions: new Map<string, { x: number; y: number }>(), contentWidth: 0, contentHeight: 0 };
    const result = computeClusteredLayout(data.nodes, data.edges, dimensions.width, dimensions.height);
    return { clusters: result.clusters, initialPositions: result.positions, contentWidth: result.totalW, contentHeight: result.totalH };
  }, [data, dimensions]);

  const nodeWidthMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const cluster of clusters) {
      for (const pn of cluster.nodes) map.set(pn.node.id, cluster.nodeW);
    }
    return map;
  }, [clusters]);

  const [nodePositions, setNodePositions] = useState<Map<string, { x: number; y: number }>>(new Map());
  useEffect(() => {
    setNodePositions(new Map(initialPositions));
    savedPositionsRef.current = null;
  }, [initialPositions]);

  // Reset state when data changes
  useEffect(() => {
    setSelectedNode(null);
    setHoveredNode(null);
    setFocusMeta(null);
    savedPositionsRef.current = null;
  }, [data]);

  // Resize observer
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) {
        setDimensions({ width: Math.max(800, entry.contentRect.width), height: Math.max(400, entry.contentRect.height) });
      }
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  // ── Derived helpers ─────────────────────────────────────────────

  const inFocus = !!focusMeta;
  const focusedNodeIds = focusMeta?.nodeIds ?? null;

  // Adaptive focus pill width
  const focusNodeW = useMemo(() => {
    if (!focusedNodeIds) return FOCUS_NODE_W;
    return focusedNodeIds.size > 13 ? MIN_NODE_W : FOCUS_NODE_W;
  }, [focusedNodeIds]);

  const getNodeWidth = useCallback((nodeId: string) => {
    if (focusedNodeIds?.has(nodeId)) return focusNodeW;
    return nodeWidthMap.get(nodeId) || MIN_NODE_W;
  }, [focusedNodeIds, focusNodeW, nodeWidthMap]);

  // ── Fit to view ─────────────────────────────────────────────────

  const fitToView = useCallback(() => {
    if (focusMeta) {
      setPan({ x: dimensions.width / 2 - focusMeta.cx * zoomRef.current, y: dimensions.height / 2 - focusMeta.cy * zoomRef.current });
    } else {
      if (contentWidth <= 0 || contentHeight <= 0) return;
      const scaleX = dimensions.width / contentWidth;
      const scaleY = dimensions.height / contentHeight;
      const newZoom = Math.min(scaleX, scaleY, 1.5) * 0.94;
      setZoom(newZoom);
      setPan({
        x: Math.max(0, (dimensions.width - contentWidth * newZoom) / 2),
        y: Math.max(0, (dimensions.height - contentHeight * newZoom) / 2),
      });
    }
  }, [focusMeta, contentWidth, contentHeight, dimensions]);

  // Reset zoom/pan when new data loads
  const prevDataKeyRef = useRef('');
  useEffect(() => {
    const key = `${data.nodes.length}-${data.edges.length}`;
    if (key !== prevDataKeyRef.current && clusters.length > 0) {
      prevDataKeyRef.current = key;
      setZoom(1);
      setPan({ x: 0, y: 0 });
    }
  }, [data.nodes.length, data.edges.length, clusters.length]);

  // ── Transitive descendant helpers ────────────────────────────────

  // Build adjacency list once for efficient traversal
  const childrenMap = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const e of data.edges) {
      if (!map.has(e.source)) map.set(e.source, []);
      map.get(e.source)!.push(e.target);
    }
    return map;
  }, [data.edges]);

  // Compute transitive descendants (BFS following source→target edges)
  const getDescendants = useCallback((nodeId: string): Set<string> => {
    const visited = new Set<string>();
    const queue = [nodeId];
    visited.add(nodeId);
    while (queue.length > 0) {
      const current = queue.shift()!;
      const children = childrenMap.get(current);
      if (children) {
        for (const child of children) {
          if (!visited.has(child)) {
            visited.add(child);
            queue.push(child);
          }
        }
      }
    }
    return visited;
  }, [childrenMap]);

  // ── Focus mode ──────────────────────────────────────────────────

  const enterFocus = useCallback((nodeId: string) => {
    // Find all transitive descendants (children, grandchildren, etc.)
    const allDescendants = getDescendants(nodeId);
    allDescendants.delete(nodeId); // Remove self, will add back later
    // Also include direct parents for context
    data.edges.forEach(e => {
      if (e.target === nodeId && e.source !== nodeId) allDescendants.add(e.source);
    });
    const connectedSet = allDescendants;

    if (connectedSet.size === 0) {
      if (savedPositionsRef.current) {
        setNodePositions(new Map(savedPositionsRef.current));
        savedPositionsRef.current = null;
      }
      setFocusMeta(null);
      return;
    }

    // Group connected nodes by type
    const typeGroups = new Map<string, string[]>();
    for (const id of connectedSet) {
      const node = data.nodes.find(n => n.id === id);
      if (!node) continue;
      if (!typeGroups.has(node.type)) typeGroups.set(node.type, []);
      typeGroups.get(node.type)!.push(id);
    }

    const basePositions = savedPositionsRef.current ?? nodePositions;
    if (!savedPositionsRef.current) {
      savedPositionsRef.current = new Map(nodePositions);
    }

    // Focus center = viewport center in SVG coords
    const curZoom = zoomRef.current;
    const curPan = panRef.current;
    const cx = (dimensions.width / 2 - curPan.x) / curZoom;
    const cy = (dimensions.height / 2 - curPan.y) / curZoom;

    const fw = focusNodeW;

    // Compute group dimensions
    const groupTypes = Array.from(typeGroups.keys()).sort();
    const groupSpecs = groupTypes.map(type => {
      const ids = typeGroups.get(type)!;
      const typeDef = OBJECT_TYPES.find(t => t.id === type);
      const label = typeDef ? typeDef.label : type.replace(/_/g, ' ');
      const color = getTypeColor(type);
      const groupH = CLUSTER_PAD_TOP + ids.length * NODE_H + (ids.length - 1) * NODE_GAP + CLUSTER_PAD_BOT;
      const groupW = fw + CLUSTER_PAD_X * 2;
      return { type, ids, label, color, groupW, groupH };
    });

    const totalGroupsW = groupSpecs.reduce((s, g) => s + g.groupW, 0) + (groupSpecs.length - 1) * FOCUS_GROUP_GAP;
    const maxGroupH = Math.max(...groupSpecs.map(g => g.groupH));

    // Selected node above the groups, groups below
    const selectedY = cy - maxGroupH / 2 - NODE_H - 20;
    const groupsTopY = cy - maxGroupH / 2;
    let groupX = cx - totalGroupsW / 2;

    const next = new Map(basePositions);
    next.set(nodeId, { x: cx, y: selectedY });

    const focusGroups: FocusGroup[] = [];

    for (const spec of groupSpecs) {
      const gx = groupX;
      const gy = groupsTopY;
      const nodeCx = gx + spec.groupW / 2;

      for (let j = 0; j < spec.ids.length; j++) {
        const ny = gy + CLUSTER_PAD_TOP + j * (NODE_H + NODE_GAP) + NODE_H / 2;
        next.set(spec.ids[j], { x: nodeCx, y: ny });
      }

      focusGroups.push({
        type: spec.type,
        label: spec.label,
        color: spec.color,
        x: gx,
        y: gy,
        w: spec.groupW,
        h: spec.groupH,
      });

      groupX += spec.groupW + FOCUS_GROUP_GAP;
    }

    const allFocusIds = new Set<string>([nodeId, ...connectedSet]);
    setNodePositions(next);
    setFocusMeta({ cx, cy, nodeIds: allFocusIds, groups: focusGroups });
  }, [data.edges, data.nodes, dimensions, nodePositions, focusNodeW, getDescendants]);

  const exitFocus = useCallback(() => {
    if (savedPositionsRef.current) {
      setNodePositions(new Map(savedPositionsRef.current));
      savedPositionsRef.current = null;
    }
    setFocusMeta(null);
  }, []);

  // ── Mouse handlers ──────────────────────────────────────────────

  const handleMouseDown = useCallback((e: React.MouseEvent, nodeId: string) => {
    if (focusMeta) return;
    e.stopPropagation();
    setDragging({ nodeId, startX: e.clientX, startY: e.clientY });
  }, [focusMeta]);

  const handleSvgMouseDown = useCallback((e: React.MouseEvent) => {
    const tag = (e.target as Element).tagName;
    if (e.target === svgRef.current || tag === 'line' || tag === 'path' || (tag === 'rect' && !(e.target as Element).closest('[data-node]'))) {
      setPanning({ startX: e.clientX, startY: e.clientY, panX: pan.x, panY: pan.y });
    }
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (dragging) {
      const pos = nodePositions.get(dragging.nodeId);
      if (!pos) return;
      const dx = (e.clientX - dragging.startX) / zoom;
      const dy = (e.clientY - dragging.startY) / zoom;
      setNodePositions(prev => {
        const next = new Map(prev);
        next.set(dragging.nodeId, { x: pos.x + dx, y: pos.y + dy });
        return next;
      });
      setDragging({ ...dragging, startX: e.clientX, startY: e.clientY });
    } else if (panning) {
      setPan({ x: panning.panX + (e.clientX - panning.startX), y: panning.panY + (e.clientY - panning.startY) });
    }
  }, [dragging, panning, nodePositions, zoom]);

  const handleMouseUp = useCallback(() => {
    if (panning && selectedNode) {
      const dx = Math.abs(pan.x - panning.panX);
      const dy = Math.abs(pan.y - panning.panY);
      if (dx < 3 && dy < 3) {
        setSelectedNode(null);
        exitFocus();
      }
    }
    setDragging(null);
    setPanning(null);
  }, [panning, pan, selectedNode, exitFocus]);

  const handleNodeClick = useCallback((nodeId: string) => {
    if (nodeId === selectedNode) {
      setSelectedNode(null);
      exitFocus();
    } else {
      setSelectedNode(nodeId);
      enterFocus(nodeId);
    }

    if (onSelectObject) {
      const node = data.nodes.find(n => n.id === nodeId);
      if (node) {
        function findObj(objs: FetchedObject[]): FetchedObject | null {
          for (const obj of objs) {
            if (obj.type === node!.type && obj.name === node!.name && obj.namespace === node!.namespace) return obj;
            for (const cg of obj.children) {
              const found = findObj(cg.objects);
              if (found) return found;
            }
          }
          return null;
        }
        const found = findObj(results);
        if (found) onSelectObject(found);
      }
    }
  }, [selectedNode, exitFocus, enterFocus, data.nodes, results, onSelectObject]);

  // Pinch-to-zoom only; two-finger scroll pans
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    if (e.ctrlKey) {
      const delta = e.deltaY > 0 ? 0.94 : 1.06;
      setZoom(z => Math.max(0.1, Math.min(3, z * delta)));
    } else {
      setPan(p => ({ x: p.x - e.deltaX, y: p.y - e.deltaY }));
    }
  }, []);

  // ── Derived data ────────────────────────────────────────────────

  const sharedObjects = useMemo(() => data.nodes.filter(n => n.parentCount >= 2), [data.nodes]);

  const connectedNodes = useMemo(() => {
    const target = hoveredNode || selectedNode;
    if (!target) return new Set<string>();
    // All transitive descendants (children, grandchildren, etc.)
    const set = getDescendants(target);
    // Also add direct parents (one level up for context)
    data.edges.forEach(e => {
      if (e.target === target) set.add(e.source);
    });
    return set;
  }, [hoveredNode, selectedNode, data.edges, getDescendants]);

  const highlightedEdges = useMemo(() => {
    const target = hoveredNode || selectedNode;
    if (!target) return new Set<string>();
    const set = new Set<string>();
    // Highlight all edges where both endpoints are in the connected set
    data.edges.forEach((e, i) => {
      if (connectedNodes.has(e.source) && connectedNodes.has(e.target)) set.add(String(i));
    });
    return set;
  }, [hoveredNode, selectedNode, data.edges, connectedNodes]);

  // Z-order: focused nodes render last (on top)
  const sortedNodes = useMemo(() => {
    if (!focusedNodeIds) return data.nodes;
    return [...data.nodes].sort((a, b) => {
      const af = focusedNodeIds.has(a.id) ? 1 : 0;
      const bf = focusedNodeIds.has(b.id) ? 1 : 0;
      return af - bf;
    });
  }, [data.nodes, focusedNodeIds]);

  // ── Early return ────────────────────────────────────────────────

  if (data.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
        <Info className="w-10 h-10 mb-3 opacity-40" />
        <p className="text-sm">No relationship data to display.</p>
        <p className="text-xs mt-1">Objects without child references won't generate a graph.</p>
      </div>
    );
  }

  const svgH = Math.max(dimensions.height, contentHeight);

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div ref={wrapperRef} className={`flex ${isFullscreen ? 'h-screen bg-slate-900' : 'h-full'}`}>
      {/* Graph area */}
      <div
        ref={containerRef}
        className="flex-1 relative bg-slate-900/50 overflow-hidden cursor-grab active:cursor-grabbing"
        style={{ minHeight: 500 }}
      >
        <svg
          ref={svgRef}
          width={dimensions.width}
          height={svgH}
          onMouseDown={handleSvgMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
          className="w-full h-full"
        >
          <defs>
            <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#475569" />
            </marker>
            <marker id="arrowhead-highlight" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <polygon points="0 0, 8 3, 0 6" fill="#3b82f6" />
            </marker>
          </defs>

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Background for panning */}
            <rect x="0" y="0" width={Math.max(dimensions.width, contentWidth) * 2} height={svgH * 2} fill="transparent" />

            {/* ── Cluster backgrounds ────────────────────────── */}
            {clusters.map(cluster => {
              const hasActive = hoveredNode || selectedNode;
              const clusterHasConnection = hasActive && cluster.nodes.some(pn => connectedNodes.has(pn.node.id));
              const bgOpacity = inFocus ? 0.02 : hasActive ? (clusterHasConnection ? 0.10 : 0.03) : 0.07;
              const strokeOpacity = inFocus ? 0.05 : hasActive ? (clusterHasConnection ? 0.35 : 0.08) : 0.18;
              const labelOpacity = inFocus ? 0.15 : hasActive ? (clusterHasConnection ? 0.95 : 0.3) : 0.8;

              return (
                <g key={`cluster-bg-${cluster.type}`}>
                  <rect
                    x={cluster.x} y={cluster.y} width={cluster.w} height={cluster.h}
                    rx="12" ry="12"
                    fill={cluster.color} fillOpacity={bgOpacity}
                    stroke={cluster.color} strokeOpacity={strokeOpacity}
                    strokeWidth="1.5" strokeDasharray="6 3"
                  />
                  <text
                    x={cluster.x + CLUSTER_PAD_X} y={cluster.y + 22}
                    fill={cluster.color} fillOpacity={labelOpacity}
                    fontSize="12" fontWeight="700" fontFamily="sans-serif"
                  >
                    {cluster.label}
                  </text>
                  <text
                    x={cluster.x + cluster.w - CLUSTER_PAD_X} y={cluster.y + 22}
                    textAnchor="end" fill={cluster.color}
                    fillOpacity={inFocus ? 0.1 : hasActive ? (clusterHasConnection ? 0.6 : 0.2) : 0.45}
                    fontSize="10" fontFamily="sans-serif"
                  >
                    {cluster.nodes.length} object{cluster.nodes.length !== 1 ? 's' : ''}
                  </text>
                </g>
              );
            })}

            {/* ── Focus mode: type group backgrounds ─────────── */}
            {focusMeta && focusMeta.groups.map(group => (
              <g key={`focus-group-${group.type}`}>
                <rect
                  x={group.x} y={group.y} width={group.w} height={group.h}
                  rx="10" ry="10"
                  fill={group.color} fillOpacity={0.08}
                  stroke={group.color} strokeOpacity={0.4}
                  strokeWidth="1.5"
                />
                <text
                  x={group.x + CLUSTER_PAD_X} y={group.y + 22}
                  fill={group.color} fillOpacity={0.9}
                  fontSize="11" fontWeight="700" fontFamily="sans-serif"
                >
                  {group.label}
                </text>
              </g>
            ))}

            {/* ── Focus mode: hint text ──────────────────────── */}
            {focusMeta && (
              <text
                x={focusMeta.cx}
                y={focusMeta.cy + Math.max(...focusMeta.groups.map(g => g.y + g.h), 0) - focusMeta.cy + 24}
                textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="sans-serif"
              >
                Click selected node or empty space to return
              </text>
            )}

            {/* ── Edges ──────────────────────────────────────── */}
            {data.edges.map((edge, i) => {
              const sourcePos = nodePositions.get(edge.source);
              const targetPos = nodePositions.get(edge.target);
              if (!sourcePos || !targetPos) return null;

              const isHighlighted = highlightedEdges.has(String(i));
              const hasActiveSelection = hoveredNode || selectedNode;
              if (hasActiveSelection && !isHighlighted) return null;
              const opacity = hasActiveSelection ? 0.85 : 0.1;

              const sourceHalfW = getNodeWidth(edge.source) / 2 + 2;
              const targetHalfW = getNodeWidth(edge.target) / 2 + 2;
              const dx = targetPos.x - sourcePos.x;
              const dy = targetPos.y - sourcePos.y;
              const sx = sourcePos.x + (dx > 0 ? sourceHalfW : -sourceHalfW);
              const sy = sourcePos.y;
              const tx = targetPos.x + (dx > 0 ? -targetHalfW : targetHalfW);
              const ty = targetPos.y;
              const dist = Math.sqrt(dx * dx + dy * dy) || 1;
              const curveStrength = Math.min(60, dist * 0.2);
              const perpX = -(ty - sy) / dist * curveStrength;
              const perpY = (tx - sx) / dist * curveStrength;
              const midX = (sx + tx) / 2 + perpX;
              const midY = (sy + ty) / 2 + perpY;

              return (
                <g key={i}>
                  <path
                    d={`M ${sx} ${sy} Q ${midX} ${midY} ${tx} ${ty}`}
                    fill="none"
                    stroke={isHighlighted ? '#3b82f6' : '#475569'}
                    strokeWidth={isHighlighted ? 2 : 0.7}
                    opacity={opacity}
                    markerEnd={isHighlighted ? 'url(#arrowhead-highlight)' : 'url(#arrowhead)'}
                  />
                  {isHighlighted && (
                    <text
                      x={midX} y={midY - 6}
                      textAnchor="middle" fill="#94a3b8"
                      fontSize="9" fontWeight="500" fontFamily="sans-serif"
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* ── Nodes (z-sorted: non-focused first, focused on top) ── */}
            {sortedNodes.map(node => {
              const pos = nodePositions.get(node.id);
              if (!pos) return null;

              const isFocused = focusedNodeIds?.has(node.id);
              const nw = isFocused ? focusNodeW : (nodeWidthMap.get(node.id) || MIN_NODE_W);
              const maxChars = Math.floor((nw - 36) / CHAR_WIDTH);
              const color = getTypeColor(node.type);
              const isShared = node.parentCount >= 2;
              const isHovered = hoveredNode === node.id;
              const isSelected = selectedNode === node.id;
              const hasActiveSelection = hoveredNode || selectedNode;
              const isConnected = connectedNodes.has(node.id);

              let nodeOpacity = 1;
              if (inFocus) {
                nodeOpacity = isFocused ? 1 : 0.07;
              } else if (hasActiveSelection) {
                nodeOpacity = isConnected ? 1 : 0.2;
              }

              const displayName = node.name.length > maxChars
                ? node.name.slice(0, maxChars - 1) + '\u2026'
                : node.name;

              return (
                <g
                  key={node.id}
                  data-node="true"
                  transform={`translate(${pos.x}, ${pos.y})`}
                  opacity={nodeOpacity}
                  onMouseDown={(e) => handleMouseDown(e, node.id)}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  onClick={() => handleNodeClick(node.id)}
                  className="cursor-pointer"
                >
                  {/* Selection glow */}
                  {isSelected && (
                    <rect
                      x={-nw / 2 - 3} y={-NODE_H / 2 - 3}
                      width={nw + 6} height={NODE_H + 6}
                      rx="8" ry="8"
                      fill="none" stroke="#3b82f6" strokeWidth="2.5"
                    />
                  )}

                  {/* Shared dashed outline */}
                  {isShared && (
                    <rect
                      x={-nw / 2 - 3} y={-NODE_H / 2 - 3}
                      width={nw + 6} height={NODE_H + 6}
                      rx="8" ry="8"
                      fill="none" stroke="#f59e0b" strokeWidth="1.5"
                      strokeDasharray="3 2" opacity={0.7}
                    />
                  )}

                  {/* Pill background */}
                  <rect
                    x={-nw / 2} y={-NODE_H / 2}
                    width={nw} height={NODE_H}
                    rx="6" ry="6"
                    fill={isHovered || isSelected ? color : '#1e293b'}
                    fillOpacity={isHovered || isSelected ? 0.25 : 0.9}
                    stroke={isHovered || isSelected ? '#fff' : color}
                    strokeWidth={isHovered || isSelected ? 1.5 : 0.8}
                    strokeOpacity={isHovered || isSelected ? 0.9 : 0.5}
                  />

                  {/* Color dot */}
                  <circle cx={-nw / 2 + 12} cy={0} r="4" fill={color} fillOpacity={0.9} />

                  {/* Root badge */}
                  {node.isRoot && (
                    <circle cx={nw / 2 - 10} cy={0} r="3.5" fill="#10b981" stroke="#0f172a" strokeWidth="1" />
                  )}

                  {/* Shared count badge */}
                  {isShared && (
                    <>
                      <circle
                        cx={nw / 2 - (node.isRoot ? 22 : 10)} cy={0}
                        r="6" fill="#f59e0b" stroke="#0f172a" strokeWidth="1"
                      />
                      <text
                        x={nw / 2 - (node.isRoot ? 22 : 10)} y={3}
                        textAnchor="middle" fill="#0f172a"
                        fontSize="7" fontWeight="bold" fontFamily="sans-serif"
                      >
                        {node.parentCount}
                      </text>
                    </>
                  )}

                  {/* Object name */}
                  <text
                    x={-nw / 2 + 22} y={4}
                    fill="#e2e8f0" fontSize="10" fontWeight="500" fontFamily="sans-serif"
                  >
                    {displayName}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* ── Legend panel ────────────────────────────────────────── */}
      <div className="w-64 flex-shrink-0 bg-slate-800/90 border-l border-slate-700 overflow-y-auto flex flex-col">
        {/* Focus mode bar */}
        {inFocus && (
          <div className="px-4 py-2.5 border-b border-blue-500/30 bg-blue-500/5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                <span className="text-xs font-semibold text-blue-400">Focus Mode</span>
              </div>
              <button
                onClick={() => { setSelectedNode(null); exitFocus(); }}
                className="text-xs text-slate-400 hover:text-white flex items-center gap-1 px-2 py-1 hover:bg-slate-700 rounded transition-colors"
              >
                <ArrowLeft className="w-3 h-3" />
                Overview
              </button>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              {connectedNodes.size - 1} connected object{connectedNodes.size - 1 !== 1 ? 's' : ''} shown
            </p>
          </div>
        )}

        {/* Toolbar */}
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700">
          <div className="flex items-center gap-1.5">
            <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded transition-colors" title="Zoom In">
              <ZoomIn className="w-4 h-4" />
            </button>
            <button onClick={() => setZoom(z => Math.max(0.1, z * 0.8))} className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded transition-colors" title="Zoom Out">
              <ZoomOut className="w-4 h-4" />
            </button>
            <button onClick={fitToView} className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded transition-colors" title="Fit to View">
              <Maximize2 className="w-4 h-4" />
            </button>
            <div className="w-px h-4 bg-slate-600 mx-0.5" />
            <button onClick={toggleFullscreen} className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded transition-colors" title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}>
              {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          </div>
          <span className="text-xs text-slate-500">{Math.round(zoom * 100)}%</span>
        </div>

        {/* Stats */}
        <div className="px-4 py-3 border-b border-slate-700">
          <p className="text-xs text-slate-500">{data.nodes.length} objects, {data.edges.length} links</p>
          {sharedObjects.length > 0 && (
            <p className="text-xs text-amber-400 mt-1">{sharedObjects.length} shared (2+ parents)</p>
          )}
        </div>

        {/* Object Types */}
        <div className="px-4 py-3 flex-1 overflow-y-auto">
          <p className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">Object Types</p>
          <div className="space-y-2.5">
            {clusters.map(cluster => (
              <div key={cluster.type} className="flex items-start gap-2.5">
                <div className="w-4 h-4 rounded-full flex-shrink-0 mt-0.5" style={{ backgroundColor: cluster.color }} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-200 leading-tight">{cluster.label}</p>
                  <p className="text-[11px] text-slate-500 font-mono">{cluster.type}</p>
                  <p className="text-[11px] text-slate-600">{cluster.nodes.length} object{cluster.nodes.length !== 1 ? 's' : ''}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Symbols */}
          <div className="mt-5 pt-4 border-t border-slate-700">
            <p className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">Symbols</p>
            <div className="space-y-2.5">
              <div className="flex items-center gap-2.5">
                <div className="w-4 h-4 rounded border-2 border-dashed border-amber-500 flex-shrink-0" />
                <div>
                  <p className="text-xs text-slate-300">Shared Object</p>
                  <p className="text-[11px] text-slate-500">Referenced by 2+ parents</p>
                </div>
              </div>
              <div className="flex items-center gap-2.5">
                <div className="w-4 h-4 rounded-full bg-emerald-500 flex-shrink-0" />
                <div>
                  <p className="text-xs text-slate-300">Root Object</p>
                  <p className="text-[11px] text-slate-500">Top-level selected object</p>
                </div>
              </div>
              <div className="flex items-center gap-2.5">
                <svg width="16" height="16" viewBox="0 0 16 16" className="flex-shrink-0">
                  <line x1="2" y1="8" x2="14" y2="8" stroke="#3b82f6" strokeWidth="2" markerEnd="url(#arrow-legend)" />
                  <defs>
                    <marker id="arrow-legend" markerWidth="6" markerHeight="4" refX="6" refY="2" orient="auto">
                      <polygon points="0 0, 6 2, 0 4" fill="#3b82f6" />
                    </marker>
                  </defs>
                </svg>
                <div>
                  <p className="text-xs text-slate-300">Dependency Link</p>
                  <p className="text-[11px] text-slate-500">Click node to focus</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Selected node detail */}
        {selectedNode && (() => {
          const node = data.nodes.find(n => n.id === selectedNode);
          if (!node) return null;
          const inEdges = data.edges.filter(e => e.target === selectedNode);
          const outEdges = data.edges.filter(e => e.source === selectedNode);
          return (
            <div className="px-4 py-3 border-t border-slate-600 bg-slate-800">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3.5 h-3.5 rounded-full" style={{ backgroundColor: getTypeColor(node.type) }} />
                <span className="text-sm font-semibold text-slate-100 truncate">{node.name}</span>
              </div>
              <div className="space-y-1 text-xs text-slate-400 mb-2">
                <p>Type: <span className="text-slate-300 font-mono">{node.type}</span></p>
                <p>Namespace: <span className="text-slate-300">{node.namespace}</span></p>
                <div className="flex gap-1 flex-wrap">
                  {node.isRoot && <span className="inline-block px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 rounded text-[10px]">Root</span>}
                  {node.parentCount >= 2 && (
                    <span className="inline-block px-1.5 py-0.5 bg-amber-500/10 text-amber-400 rounded text-[10px]">
                      Shared ({node.parentCount} parents)
                    </span>
                  )}
                </div>
              </div>
              {inEdges.length > 0 && (
                <div className="mb-2">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wide mb-1">Referenced by ({inEdges.length})</p>
                  {inEdges.map((e, i) => {
                    const src = data.nodes.find(n => n.id === e.source);
                    return (
                      <p key={i} className="text-xs text-slate-400 truncate">
                        <span className="text-slate-300">{src?.name}</span> <span className="text-slate-600">via</span> {e.label}
                      </p>
                    );
                  })}
                </div>
              )}
              {outEdges.length > 0 && (
                <div>
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wide mb-1">References ({outEdges.length})</p>
                  {outEdges.map((e, i) => {
                    const tgt = data.nodes.find(n => n.id === e.target);
                    return (
                      <p key={i} className="text-xs text-slate-400 truncate">
                        <span className="text-slate-300">{tgt?.name}</span> <span className="text-slate-600">as</span> {e.label}
                      </p>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })()}
      </div>
    </div>
  );
}
