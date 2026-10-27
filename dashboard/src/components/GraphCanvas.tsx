import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { GraphData, GraphEdge, GraphNode } from '../types.ts';
import { href } from '../router.ts';
import { Empty } from './ui.tsx';

const TYPE_STYLE: Record<string, { color: string; shape: cytoscape.Css.NodeShape }> = {
  Incident: { color: '#f0506e', shape: 'round-diamond' },
  Asset: { color: '#5b9dff', shape: 'round-rectangle' },
  Identity: { color: '#3fbf7f', shape: 'ellipse' },
  IOC: { color: '#f59b42', shape: 'round-triangle' },
  TTP: { color: '#b9a4fb', shape: 'round-hexagon' },
};

type Selected = { kind: 'node'; node: GraphNode } | { kind: 'edge'; edge: GraphEdge } | null;

export const GraphCanvas: React.FC<{ graph: GraphData; tall?: boolean }> = ({ graph, tall }) => {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<Selected>(null);

  useEffect(() => {
    if (!ref.current || graph.nodes.length === 0) return;
    const centers = new Set(graph.centers);
    const cy = cytoscape({
      container: ref.current,
      elements: [
        ...graph.nodes.map((n) => ({
          data: { id: n.id, label: n.name.length > 34 ? n.name.slice(0, 32) + '…' : n.name, type: n.label },
          classes: centers.has(n.id) ? 'center' : '',
        })),
        ...graph.edges.map((e) => ({
          data: { id: e.id, source: e.source, target: e.target, label: `${e.type}${e.confidence != null ? ` ${Number(e.confidence).toFixed(2)}` : ''}` },
        })),
      ],
      style: [
        {
          selector: 'node',
          style: {
            'background-color': (ele: cytoscape.NodeSingular) => TYPE_STYLE[ele.data('type')]?.color ?? '#7b879a',
            shape: (ele: cytoscape.NodeSingular) => TYPE_STYLE[ele.data('type')]?.shape ?? 'ellipse',
            label: 'data(label)',
            color: '#d5dce7',
            'font-size': 11,
            'text-valign': 'bottom',
            'text-margin-y': 5,
            width: 26,
            height: 26,
            'border-width': 0,
            'text-wrap': 'wrap',
            'text-max-width': '140px',
          },
        },
        { selector: 'node.center', style: { width: 34, height: 34, 'border-width': 2, 'border-color': '#e6ebf2' } },
        { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#5b9dff' } },
        {
          selector: 'edge',
          style: {
            width: 1.4,
            'line-color': '#3a4a64',
            'target-arrow-color': '#3a4a64',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 8,
            color: '#7b879a',
            'text-rotation': 'autorotate',
            'text-background-color': '#0e131c',
            'text-background-opacity': 1,
            'text-background-padding': '2px',
          },
        },
        { selector: 'edge:selected', style: { 'line-color': '#5b9dff', 'target-arrow-color': '#5b9dff', width: 2.4 } },
      ],
      layout: {
        name: 'cose', animate: false, fit: true, padding: 40, randomize: false,
        nodeRepulsion: () => 60000, idealEdgeLength: () => 70, nodeOverlap: 20,
        componentSpacing: 40, gravity: 0.8, numIter: 2500,
      },
      wheelSensitivity: 0.25,
    });
    cy.on('tap', 'node', (evt) => {
      const node = graph.nodes.find((n) => n.id === evt.target.id());
      if (node) setSelected({ kind: 'node', node });
    });
    cy.on('tap', 'edge', (evt) => {
      const edge = graph.edges.find((e) => e.id === evt.target.id());
      if (edge) setSelected({ kind: 'edge', edge });
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelected(null);
    });
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  if (graph.nodes.length === 0) return <Empty title="No graph entities" hint="This view has no resolved entities yet." />;

  return (
    <div className={`graph-wrap${tall ? ' tall' : ''}`}>
      <div ref={ref} style={{ position: 'absolute', inset: 0 }} role="img" aria-label={`Entity graph with ${graph.nodes.length} nodes and ${graph.edges.length} relationships`} />
      <div className="graph-legend" aria-hidden="true">
        {Object.entries(TYPE_STYLE).map(([type, s]) => (
          <span key={type} className="row" style={{ gap: 4 }}><span className="dot" style={{ background: s.color }} />{type}</span>
        ))}
        <span>· click a node or edge for provenance</span>
      </div>
      {selected && (
        <div className="graph-side">
          {selected.kind === 'node' ? (
            <div className="stack" style={{ gap: 8 }}>
              <div className="row"><span className="badge neutral">{selected.node.label}</span></div>
              <div style={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{selected.node.name}</div>
              <div className="hash" style={{ overflowWrap: 'anywhere' }}>{selected.node.id}</div>
              {selected.node.confidence != null && <div className="muted">Resolution confidence: {Number(selected.node.confidence).toFixed(2)}</div>}
              <div className="row">
                <a className="btn sm" href={`${href('graph')}?entity=${encodeURIComponent(selected.node.id)}`}>Explore neighborhood</a>
                {selected.node.alert_id && <a className="btn sm" href={href('alerts', selected.node.alert_id)}>Open alert</a>}
                {selected.node.incident_id && <a className="btn sm" href={href('incidents', selected.node.incident_id)}>Open incident</a>}
              </div>
            </div>
          ) : (
            <dl className="kv" style={{ gridTemplateColumns: '84px 1fr' }}>
              <dt>Relation</dt><dd><strong>{selected.edge.type}</strong></dd>
              <dt>From</dt><dd className="hash">{selected.edge.source}</dd>
              <dt>To</dt><dd className="hash">{selected.edge.target}</dd>
              <dt>Confidence</dt><dd>{selected.edge.confidence != null ? Number(selected.edge.confidence).toFixed(2) : '—'}</dd>
              <dt>Source</dt><dd>{selected.edge.provenance ?? '—'}</dd>
              <dt>Valid from</dt><dd className="mono">{selected.edge.valid_from ?? '—'}</dd>
              <dt>Last seen</dt><dd className="mono">{selected.edge.last_seen ?? '—'}</dd>
            </dl>
          )}
          <button className="btn sm ghost" style={{ marginTop: 8 }} onClick={() => setSelected(null)}>Close</button>
        </div>
      )}
    </div>
  );
};
