import React, { useState } from 'react';
import { ShieldAlert, ChevronLeft } from 'lucide-react';

export default function AlertNavigation({ alerts = [], selectedAlertId, onSelectAlert, onCollapse }) {
  const [filter, setFilter] = useState('ALL');

  const filteredAlerts = filter === 'ALL'
    ? alerts
    : alerts.filter(alert => alert.severityLevel === filter);

  const priorities = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="alert-navigation-sidebar panel">
      <div className="sidebar-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ShieldAlert size={14} style={{ color: 'var(--color-primary)' }} />
            <span>Security Incidents</span>
            <span className="alert-counter">{filteredAlerts.length}</span>
          </h3>
          <button 
            onClick={onCollapse}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '4px',
              transition: 'background-color 0.15s ease'
            }}
            title="Collapse Sidebar"
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = '#1a2230'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
          >
            <ChevronLeft size={14} />
          </button>
        </div>

        <div className="priority-filters">
          {priorities.map(p => (
            <button
              key={p}
              className={`filter-btn ${filter === p ? 'active' : ''} ${filter === p ? p.toLowerCase() : ''}`}
              onClick={() => setFilter(p)}
            >
              {p === 'ALL' ? 'All' : p}
            </button>
          ))}
        </div>
      </div>

      <div className="alerts-list">
        {filteredAlerts.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px', fontSize: '0.8rem' }}>
            No matching incidents.
          </div>
        ) : (
          filteredAlerts.map(alert => {
            const isSelected = alert.alertId === selectedAlertId;
            const severityClass = alert.severityLevel.toLowerCase();
            return (
              <div
                key={alert.alertId}
                className={`alert-item ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelectAlert(alert.alertId)}
              >
                <div className="alert-item-header">
                  <span className={`alert-severity-indicator ${severityClass}`}>
                    {alert.severityLevel}
                  </span>
                  <span className={`alert-score-badge ${severityClass}`}>
                    {Math.round(alert.riskPercentage)}
                  </span>
                </div>
                <div className="alert-item-name">{alert.eventSummary}</div>
                <div className="alert-item-time">
                  {new Date(alert.triggeringEvent.payload.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
