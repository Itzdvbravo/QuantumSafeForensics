import React, { useState, useEffect } from 'react';
import {
  User, Clock, Terminal, AlertOctagon, Scale, ShieldCheck,
  GitBranch, Server, Database, Key, Mail, ShieldAlert,
  FileText, CheckCircle, Fingerprint, Loader, Lock, PowerOff
} from 'lucide-react';
import GraphVisualization from './GraphVisualization';

// Pick an action-type icon for historic timeline events
function getActionIcon(action = '') {
  const a = action.toUpperCase();
  if (a.includes('AUTH') || a.includes('LOGIN') || a.includes('LOGON'))
    return <Fingerprint size={13} />;
  if (a.includes('EXPORT') || a.includes('FILE') || a.includes('DOWNLOAD') || a.includes('UPLOAD'))
    return <FileText size={13} />;
  if (a.includes('QUERY') || a.includes('QUERIED') || a.includes('DATABASE'))
    return <Database size={13} />;
  if (a.includes('KEY') || a.includes('PRIVILEGE') || a.includes('PERMISSION'))
    return <Key size={13} />;
  if (a.includes('EMAIL') || a.includes('PHISH') || a.includes('MAIL'))
    return <Mail size={13} />;
  if (a.includes('LOGOUT') || a.includes('LOGGED_OUT'))
    return <CheckCircle size={13} />;
  return <Terminal size={13} />;
}

// Derive a risk class from riskPoints
function riskClass(points = 0) {
  if (points >= 50) return 'critical';
  if (points >= 35) return 'high';
  if (points >= 20) return 'medium';
  return 'low';
}

function getEntityRelationship(entity, alertedUser) {
  if (entity.name === alertedUser) {
    return "Root Compromised Identity";
  }
  const interactions = entity.interactions || [];
  if (interactions.length === 0) return "Correlated Entity";

  const intx = interactions[0];
  if (intx.source === "BACKWARD_CHAIN") {
    if (intx.performed_by) return `Backward Chain: accessed by ${intx.performed_by}`;
    if (intx.target_asset) return `Backward Chain: accessed ${intx.target_asset}`;
    return `Backward Chain: ${intx.action}`;
  }
  if (intx.source === "BLAST_RADIUS") {
    const hopText = intx.hop ? ` (Hop ${intx.hop})` : "";
    if (intx.accessed_by) return `Blast Radius${hopText}: accessed by ${intx.accessed_by}`;
    if (intx.target_asset) return `Blast Radius${hopText}: accessed ${intx.target_asset}`;
    return `Blast Radius${hopText}: ${intx.action}`;
  }
  return "Correlated Activity";
}

export default function AlertDetail({ alert }) {
  const [showGraph, setShowGraph] = useState(false);
  const [focusEntity, setFocusEntity] = useState(null);
  const [popupMessage, setPopupMessage] = useState(null);

  useEffect(() => {
    setShowGraph(false);
    setFocusEntity(null);
    setPopupMessage(null);
  }, [alert?.alertId]);
  if (!alert) {
    return (
      <div className="alert-detail-container panel" style={{ padding: '32px', textAlign: 'center', color: 'var(--text-secondary)' }}>
        Select an incident from the log registry to start analysis.
      </div>
    );
  }

  const {
    alertId,
    eventSummary,
    riskPercentage,
    severityLevel,
    alertedUser,
    triggeringEvent,
    triggeringQuery,
    maliciousIndicators = [],
    benignFactors = [],
    historicActions = [],
    assetsAndUsers = [],
    detailLoading = false,
  } = alert;

  const severityClass = severityLevel.toLowerCase();

  // Thin gauge circle SVG math — riskPercentage is already 0–100
  const radius = 18;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (riskPercentage / 100) * circumference;

  // Derive crypto signature fields from triggeringEvent
  const signature = triggeringEvent?.qpc_signature;
  const signatureStatus = triggeringEvent?.signatureVerified ? 'verified' : 'tampered';
  const signatureNode = triggeringEvent?.payload?.target_asset;
  const hasCryptoSignature = !!signature;

  return (
    <div className="alert-detail-container">

      {/* Risk Score & Trigger Event Banner */}
      <div className="alert-details-header panel">
        <div className="alert-details-title-area">
          <div className="title-badge-pair">
            <div className="risk-wheel-container">
              <svg className="risk-wheel-svg">
                <circle className="risk-circle-bg" cx="22" cy="22" r={radius} />
                <circle
                  className={`risk-circle-val ${severityClass}`}
                  cx="22" cy="22" r={radius}
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                />
              </svg>
              <div className={`risk-score-text ${severityClass}`}>{Math.round(riskPercentage)}</div>
            </div>
            <div>
              <h2>{eventSummary}</h2>
              <div className="alert-details-meta">
                <div className="alert-details-meta-item">
                  <User size={13} style={{ color: 'var(--text-muted)' }} />
                  <span>Associated Identity: <strong>{alertedUser}</strong></span>
                </div>
                <div className="alert-details-meta-item">
                  <Clock size={13} style={{ color: 'var(--text-muted)' }} />
                  <span>Trigger Log ID: <strong>{triggeringEvent?.log_id}</strong></span>
                </div>
                <div className="alert-details-meta-item">
                  <Terminal size={13} style={{ color: 'var(--text-muted)' }} />
                  <span>Time detected: <strong>{new Date(triggeringEvent?.payload?.timestamp).toLocaleString()}</strong></span>
                </div>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', alignItems: 'flex-end' }}>
            <span className={`alert-severity-indicator ${severityClass}`} style={{ height: 'fit-content' }}>
              {severityLevel}
            </span>
            <button
              onClick={() => setShowGraph(true)}
              style={{
                background: 'var(--color-primary)', color: '#fff', border: 'none', borderRadius: '4px',
                padding: '6px 12px', fontSize: '0.75rem', cursor: 'pointer', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px'
              }}>
              <GitBranch size={13} /> Visualize Interaction
            </button>
          </div>
        </div>

        <div className="trigger-event-box">
          <div className="trigger-title">
            <ShieldAlert size={12} style={{ color: 'var(--color-primary)' }} />
            <span>Triggering Incident Query</span>
          </div>
          <pre className="trigger-code">
            <code>{triggeringQuery}</code>
          </pre>
        </div>

        {hasCryptoSignature && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: signatureStatus === 'tampered' ? 'var(--color-critical-light)' : 'var(--color-low-light)',
              border: `1px solid ${signatureStatus === 'tampered' ? 'var(--color-critical)' : 'var(--color-low)'}`,
              borderRadius: '4px',
              padding: '8px 12px',
              marginTop: '10px',
              flexWrap: 'nowrap',
              gap: '12px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              {signatureStatus === 'tampered' ? (
                <ShieldAlert size={13} style={{ color: 'var(--color-critical)' }} />
              ) : (
                <ShieldCheck size={13} style={{ color: 'var(--color-low)' }} />
              )}
              <span style={{ fontSize: '0.75rem', fontWeight: 600, whiteSpace: 'nowrap' }}>
                Cryptographic Signature Integrity ({signatureNode})
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: 0, flexWrap: 'nowrap' }}>
              <span
                title={signature}
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.65rem',
                  color: 'var(--text-secondary)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  flex: 1,
                  minWidth: 0
                }}
              >
                {signature.slice(0, 100)}...
              </span>
              <span
                className={`alert-severity-indicator ${signatureStatus === 'tampered' ? 'critical' : 'low'}`}
                style={{ fontSize: '0.6rem', padding: '1px 4px', flexShrink: 0, whiteSpace: 'nowrap' }}
              >
                {signatureStatus === 'tampered' ? 'Tamper Detected' : 'Verified'}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Evidence Matrix */}
      <div className="matrix-grid">
        {/* Prosecution Card */}
        <div className="matrix-card panel prosecution">
          <div className="matrix-card-header">
            <Scale size={15} style={{ color: 'var(--color-prosecution)' }} />
            <h3 className="matrix-card-title">Indictment Indicators (Malicious)</h3>
          </div>
          <div className="matrix-list">
            {maliciousIndicators.map((item, idx) => (
              <div key={idx} className="matrix-item">
                <AlertOctagon size={14} className="matrix-item-icon" />
                <div className="matrix-item-text">
                  <span className="matrix-item-label">{item.title}</span>
                  <span className="matrix-item-desc">{item.description}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Defense Card */}
        <div className="matrix-card panel defense">
          <div className="matrix-card-header">
            <ShieldCheck size={15} style={{ color: 'var(--color-defense)' }} />
            <h3 className="matrix-card-title">Contextual Mitigations (Benign)</h3>
          </div>
          <div className="matrix-list">
            {benignFactors.length > 0 ? (
              benignFactors.map((item, idx) => (
                <div key={idx} className="matrix-item">
                  <CheckCircle size={14} className="matrix-item-icon" />
                  <div className="matrix-item-text">
                    <span className="matrix-item-label">{item.title}</span>
                    <span className="matrix-item-desc">{item.description}</span>
                  </div>
                </div>
              ))
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', padding: '8px 0', fontStyle: 'italic' }}>
                No mitigating factors identified.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Root-Cause Reconstruction Timeline — historicActions */}
      <div className="timeline-card panel">
        <div className="section-header-box">
          <h3 className="section-title">
            <GitBranch size={14} style={{ color: 'var(--color-primary)' }} />
            <span>Root-Cause Reconstruction Timeline</span>
          </h3>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Chronological Trace</span>
        </div>

        {detailLoading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '20px 16px', color: 'var(--text-muted)', fontSize: '0.8rem', borderTop: '1px solid var(--border-color)' }}>
            <Loader size={14} style={{ animation: 'spin 1s linear infinite' }} />
            Loading timeline...
          </div>
        ) : historicActions.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '20px 16px', color: 'var(--text-muted)', fontSize: '0.82rem', fontStyle: 'italic', borderTop: '1px solid var(--border-color)' }}>
            <GitBranch size={16} style={{ color: 'var(--color-primary)', opacity: 0.5, flexShrink: 0 }} />
            Detailed timeline available in full forensic report.
          </div>
        ) : (
          <div className="timeline-list">
            {historicActions.map((evt, idx) => {
              const isLast = idx === historicActions.length - 1;
              const isFirst = idx === 0;
              let statusClass = 'active';
              if (isLast) statusClass = 'critical';
              else if (isFirst) statusClass = 'warning';

              const rc = riskClass(evt.riskPoints);

              return (
                <div key={evt.log_id ?? idx} className={`timeline-event ${statusClass}`}>
                  <div className="timeline-dot"></div>
                  <div className="timeline-event-content">
                    <div className="timeline-event-header">
                      <div className="timeline-event-title">
                        {getActionIcon(evt.action)}
                        <span>{evt.action}</span>
                        {evt.target_asset && (
                          <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '0.75em' }}>
                            → {evt.target_asset}
                          </span>
                        )}
                      </div>
                      <span className={`alert-severity-indicator ${rc}`} style={{ fontSize: '0.6rem', padding: '1px 5px' }}>
                        +{evt.riskPoints ?? 0} pts
                      </span>
                    </div>
                    <div className="timeline-event-meta">
                      <span>Log ID: {evt.log_id}</span>
                      <span>•</span>
                      <span>{new Date(evt.timestamp).toLocaleString()}</span>
                    </div>
                    {evt.riskReasons && evt.riskReasons.length > 0 && (
                      <div className="timeline-event-metadata">
                        {evt.riskReasons.join(' · ')}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Lateral Contamination — assetsAndUsers */}
      <div className="lateral-card panel">
        <div className="section-header-box">
          <h3 className="section-title">
            <Server size={14} style={{ color: 'var(--color-primary)' }} />
            <span>Lateral Contamination (Exposed Assets)</span>
          </h3>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Pivot Index</span>
        </div>

        {detailLoading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '20px 16px', color: 'var(--text-muted)', fontSize: '0.8rem', borderTop: '1px solid var(--border-color)' }}>
            <Loader size={14} style={{ animation: 'spin 1s linear infinite' }} />
            Loading asset graph...
          </div>
        ) : assetsAndUsers.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '20px 16px', color: 'var(--text-muted)', fontSize: '0.82rem', fontStyle: 'italic', borderTop: '1px solid var(--border-color)' }}>
            <Server size={16} style={{ color: 'var(--color-primary)', opacity: 0.5, flexShrink: 0 }} />
            Asset exposure graph available via deep forensic query.
          </div>
        ) : (
          <div className="lateral-sections-container" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {(() => {
              const renderEntityCard = (entity, idx) => {
                const pct = Math.round(entity.risk_percentage || 0);
                const entityType = (entity.entityType || entity.role || '').toUpperCase();

                let entityIcon = <Server size={13} />;
                if (entityType === 'USER') entityIcon = <User size={13} />;
                else if (entityType === 'DATABASE') entityIcon = <Database size={13} />;
                else if (entityType === 'FILE') entityIcon = <FileText size={13} />;

                let pctColor = 'var(--color-low)';
                if (pct >= 65) pctColor = 'var(--color-critical)';
                else if (pct >= 50) pctColor = 'var(--color-high)';
                else if (pct >= 35) pctColor = 'var(--color-medium)';

                return (
                  <div
                    key={`${entity.name}-${idx}`}
                    className="lateral-item"
                    onClick={() => setFocusEntity(entity.name)}
                    title={`Click to visualize interaction for ${entity.name}`}
                  >
                    <div className="lateral-entity-info">
                      <div className="lateral-icon-box">
                        {entityIcon}
                      </div>
                      <div className="lateral-entity-details">
                        <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
                          <span className="lateral-entity-name" title={entity.name}>{entity.name}</span>
                          <span className="lateral-entity-type">{entityType}</span>
                        </div>
                        <span className="lateral-entity-relation">
                          {getEntityRelationship(entity, alertedUser)}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px', flexShrink: 0 }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.78rem',
                        fontWeight: 700,
                        color: pctColor,
                        letterSpacing: '0.02em',
                      }}>
                        {pct}%
                      </span>
                      <div className="lateral-action-hint">
                        <GitBranch size={10} />
                        <span>Visualize</span>
                      </div>
                    </div>
                  </div>
                );
              };

              const rootIdentity = assetsAndUsers.filter(e => e.name === alertedUser);
              const backwardChain = assetsAndUsers.filter(e => e.name !== alertedUser && (!e.interactions || e.interactions.length === 0 || e.interactions[0].source === 'BACKWARD_CHAIN'));
              const blastRadius = assetsAndUsers.filter(e => e.name !== alertedUser && e.interactions && e.interactions.length > 0 && e.interactions[0].source === 'BLAST_RADIUS');

              return (
                <>
                  {rootIdentity.length > 0 && (
                    <div className="lateral-section">
                      <h4 className="lateral-section-title">Root Compromised Identity</h4>
                      <div className="lateral-grid">
                        {rootIdentity.map(renderEntityCard)}
                      </div>
                    </div>
                  )}
                  {backwardChain.length > 0 && (
                    <div className="lateral-section">
                      <h4 className="lateral-section-title">Backward Chain (Historical Context)</h4>
                      <div className="lateral-grid">
                        {backwardChain.map(renderEntityCard)}
                      </div>
                    </div>
                  )}
                  {blastRadius.length > 0 && (
                    <div className="lateral-section">
                      <h4 className="lateral-section-title">Blast Radius (Forward Exposure)</h4>
                      <div className="lateral-grid">
                        {blastRadius.map(renderEntityCard)}
                      </div>
                    </div>
                  )}
                </>
              );
            })()}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: '16px', marginTop: '24px', padding: '16px', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px', justifyContent: 'flex-end' }}>
        <button
          onClick={() => setPopupMessage("This feature will immediately lock the user's account across all systems, revoking their active sessions and preventing further access.")}
          style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, fontSize: '0.85rem' }}
        >
          <Lock size={14} /> Suspend User
        </button>
        <button
          onClick={() => setPopupMessage("This feature will place a forensic hold on the affected assets, isolating them from the network to prevent further lateral movement.")}
          style={{ background: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.2)', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, fontSize: '0.85rem' }}
        >
          <ShieldAlert size={14} /> Isolate Assets
        </button>
        <button
          onClick={() => setPopupMessage("This feature will gracefully shut down the associated application server to immediately halt all processing and protect remaining systems.")}
          style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.4)', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, fontSize: '0.85rem' }}
        >
          <PowerOff size={14} /> Emergency Shutdown
        </button>
      </div>

      {showGraph && <GraphVisualization alertId={alertId} onClose={() => setShowGraph(false)} />}
      {focusEntity && <GraphVisualization alertId={alertId} focusEntityName={focusEntity} onClose={() => setFocusEntity(null)} />}

      {popupMessage && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)', zIndex: 9999,
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <div className="panel" style={{ padding: '24px', maxWidth: '400px', textAlign: 'center', background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
            <h3 style={{ marginTop: 0, color: 'var(--text-primary)' }}>Under Development</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '24px' }}>
              {popupMessage}
            </p>
            <button
              onClick={() => setPopupMessage(null)}
              style={{ background: 'var(--color-primary)', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', fontWeight: 600 }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
