import React, { useState, useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  MarkerType,
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import { X, Loader, User, Server, Database, ShieldAlert } from 'lucide-react';

const nodeWidth = 240;
const nodeHeight = 65;

const getLayoutedElements = (nodes, edges, direction = 'LR') => {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  const isHorizontal = direction === 'LR';
  dagreGraph.setGraph({ rankdir: direction, ranksep: 120, nodesep: 60 });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const newNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      targetPosition: isHorizontal ? 'left' : 'top',
      sourcePosition: isHorizontal ? 'right' : 'bottom',
      position: {
        x: nodeWithPosition.x - nodeWidth / 2,
        y: nodeWithPosition.y - nodeHeight / 2,
      },
    };
  });

  return { nodes: newNodes, edges };
};

// --- Custom Node Component ---
const EntityNode = ({ data, isConnectable }) => {
  const isHighRisk = data.isAlerting || data.severity === 'HIGH' || data.severity === 'CRITICAL' || data.isUnauthorized;
  
  let Icon = Server;
  if (data.type === 'USER') Icon = User;
  if (data.type === 'DATABASE') Icon = Database;

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      background: 'var(--bg-surface)',
      border: `1px solid ${isHighRisk ? 'var(--color-critical)' : 'var(--border-color)'}`,
      borderRadius: '8px',
      padding: '12px 16px',
      width: `${nodeWidth}px`,
      boxShadow: isHighRisk ? '0 0 16px rgba(239, 68, 68, 0.15)' : '0 4px 12px rgba(0,0,0,0.2)',
      color: 'var(--text-primary)'
    }}>
      <Handle type="target" position={Position.Left} isConnectable={isConnectable} style={{ background: '#64748b', border: 'none', width: 6, height: 6 }} />
      
      <div style={{
        background: data.type === 'USER' ? 'var(--color-low-light)' : 'rgba(255,255,255,0.05)',
        color: data.type === 'USER' ? 'var(--color-low)' : 'var(--text-secondary)',
        padding: '10px',
        borderRadius: '6px',
        display: 'flex', alignItems: 'center', justifyContent: 'center'
      }}>
        <Icon size={18} />
      </div>
      
      <div style={{ flex: 1, overflow: 'hidden' }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 600, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={data.label}>
          {data.label}
        </div>
        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', letterSpacing: '0.02em', textTransform: 'uppercase', marginTop: '2px' }}>
          {data.type} {data.isAlerting && '(Subject)'}
        </div>
      </div>
      
      {isHighRisk && (
        <ShieldAlert size={16} style={{ color: 'var(--color-critical)', flexShrink: 0 }} />
      )}
      
      <Handle type="source" position={Position.Right} isConnectable={isConnectable} style={{ background: '#64748b', border: 'none', width: 6, height: 6 }} />
    </div>
  );
};

const nodeTypes = { entity: EntityNode };

// --- Custom Edge Component ---
const MultiEdge = ({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, style, markerEnd, data }) => {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition
  });

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={style} markerEnd={markerEnd} />
      <EdgeLabelRenderer>
        <div
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            background: 'var(--bg-deep)',
            padding: '4px 8px',
            borderRadius: '4px',
            border: '1px solid var(--border-color)',
            fontSize: '11px',
            fontWeight: 500,
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-primary)',
            pointerEvents: 'all',
            display: 'flex',
            flexDirection: 'column',
            gap: '2px',
            alignItems: 'center',
            zIndex: 10,
          }}
          className="nodrag nopan"
        >
          {data.labels.map((lbl, idx) => (
            <div key={idx} style={{ whiteSpace: 'nowrap', color: lbl.isHighRisk ? '#ef4444' : 'inherit' }}>
              {lbl.text}
            </div>
          ))}
        </div>
      </EdgeLabelRenderer>
    </>
  );
};

const edgeTypes = { multi: MultiEdge };

export default function GraphVisualization({ alertId, focusEntityName, onClose }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    fetch(`/api/alerts/${alertId}/graph`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP error! status: ${r.status}`);
        return r.json();
      })
      .then(data => {
        let apiNodes = data.nodes || [];
        let apiEdges = data.edges || [];

        if (focusEntityName) {
           apiEdges = apiEdges.filter(e => e.source === focusEntityName || e.target === focusEntityName);
           const connectedNodeIds = new Set([focusEntityName]);
           apiEdges.forEach(e => {
             connectedNodeIds.add(e.source);
             connectedNodeIds.add(e.target);
           });
           apiNodes = apiNodes.filter(n => connectedNodeIds.has(n.id));
        }

        const rfNodes = apiNodes.map(n => ({
          id: n.id,
          type: 'entity',
          data: { ...n },
          position: { x: 0, y: 0 }
        }));

        const groupedEdges = {};
        apiEdges.forEach(e => {
          const key = `${e.source}->${e.target}`;
          if (!groupedEdges[key]) groupedEdges[key] = [];
          groupedEdges[key].push(e);
        });

        const rfEdges = Object.values(groupedEdges).map(edgeGroup => {
          const id = edgeGroup.map(e => e.id).join('_');
          const source = edgeGroup[0].source;
          const target = edgeGroup[0].target;
          const isHighRisk = edgeGroup.some(e => e.isHighRisk);
          const totalBytes = edgeGroup.reduce((sum, e) => sum + (e.bytes || 0), 0);
          
          const labels = edgeGroup.map(e => ({
            text: `${e.action} ${e.count > 1 ? `(${e.count})` : ''}`,
            isHighRisk: e.isHighRisk
          }));

          return {
            id,
            source,
            target,
            animated: isHighRisk,
            style: { 
              stroke: isHighRisk ? '#ef4444' : '#64748b', 
              strokeWidth: Math.max(1.5, Math.min(3, Math.sqrt(totalBytes / 10000))) 
            },
            type: 'multi',
            data: { labels },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: isHighRisk ? '#ef4444' : '#64748b',
            },
          };
        });

        const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(rfNodes, rfEdges, 'LR');
        
        setNodes(layoutedNodes);
        setEdges(layoutedEdges);
        setLoading(false);
      })
      .catch(e => {
        setError(e.message);
        setLoading(false);
      });
  }, [alertId, focusEntityName, setNodes, setEdges]);

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(4px)',
      zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center'
    }}>
      <div className="panel" style={{
        width: '90vw', height: '90vh',
        display: 'flex', flexDirection: 'column',
        position: 'relative', overflow: 'hidden'
      }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '16px 24px', borderBottom: '1px solid var(--border-color)',
          background: 'var(--bg-surface)'
        }}>
          <h2 style={{ margin: 0, fontSize: '1.2rem', color: 'var(--text-primary)' }}>
            {focusEntityName ? `Interaction Diagram: ${focusEntityName}` : `Architecture Diagram: ${alertId}`}
          </h2>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4px'
          }}>
            <X size={20} />
          </button>
        </div>
        
        <div style={{ flex: 1, position: 'relative', background: 'var(--bg-deep)' }}>
          {loading && (
            <div style={{
              position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--text-muted)',
              zIndex: 10
            }}>
              <Loader size={24} style={{ marginRight: '8px', animation: 'spin 1s linear infinite' }} /> Loading architecture diagram...
            </div>
          )}
          {error && (
            <div style={{
              position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--color-critical)',
              zIndex: 10
            }}>
              Failed to load graph: {error}
            </div>
          )}
          
          {!loading && !error && nodes.length > 0 && (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              minZoom={0.1}
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#334155" gap={20} size={1} />
              <Controls style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', color: 'var(--text-primary)' }} />
            </ReactFlow>
          )}
        </div>
      </div>
    </div>
  );
}
