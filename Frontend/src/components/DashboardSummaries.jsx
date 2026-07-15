import React from 'react';
import { AlertTriangle, ShieldAlert, KeyRound, Network } from 'lucide-react';

export default function DashboardSummaries({ alerts = [] }) {
  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter(a => a.severityLevel === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severityLevel === 'HIGH').length;

  const avgRiskScore = totalAlerts > 0
    ? Math.round(alerts.reduce((acc, curr) => acc + curr.riskPercentage, 0) / totalAlerts)
    : 0;

  let threatLabel = 'Low';
  let riskColor = 'var(--color-low)';
  if (avgRiskScore >= 90) {
    threatLabel = 'Critical';
    riskColor = 'var(--color-critical)';
  } else if (avgRiskScore >= 70) {
    threatLabel = 'High';
    riskColor = 'var(--color-high)';
  } else if (avgRiskScore >= 40) {
    threatLabel = 'Medium';
    riskColor = 'var(--color-medium)';
  }

  return (
    <div className="summaries-container">
      {/* Aggregate Threat Index */}
      <div className="summary-card panel">
        <div className="summary-info">
          <h4>Aggregate Threat Index</h4>
          <div className="summary-val">{avgRiskScore}%</div>
          <div className="summary-subtext">
            Status: <span style={{ color: riskColor, fontWeight: 600 }}>{threatLabel}</span>
          </div>
        </div>
        <div className="summary-icon-box">
          <AlertTriangle size={18} />
        </div>
      </div>

      {/* Active Incidents */}
      <div className="summary-card panel">
        <div className="summary-info">
          <h4>Active Incidents</h4>
          <div className="summary-val">{totalAlerts}</div>
          <div className="summary-subtext">
            <span style={{ color: 'var(--color-critical)', fontWeight: 500 }}>{criticalCount} Critical</span>
            {' • '}
            <span style={{ color: 'var(--color-high)', fontWeight: 500 }}>{highCount} High</span>
          </div>
        </div>
        <div className="summary-icon-box">
          <ShieldAlert size={18} />
        </div>
      </div>

      {/* Quantum Cryptography Status */}
      <div className="summary-card panel" style={{ opacity: 0.7 }}>
        <div className="summary-info">
          <h4>Encrypted Vaults</h4>
          <div className="summary-val" style={{ fontSize: '1.1rem', color: 'var(--text-muted)', margin: '4px 0' }}>Under Development</div>
          <div className="summary-subtext">Quantum cryptography vault integration pending</div>
        </div>
        <div className="summary-icon-box">
          <KeyRound size={18} />
        </div>
      </div>

      {/* Network Assets Monitor */}
      <div className="summary-card panel" style={{ opacity: 0.7 }}>
        <div className="summary-info">
          <h4>Monitored Nodes</h4>
          <div className="summary-val" style={{ fontSize: '1.1rem', color: 'var(--text-muted)', margin: '4px 0' }}>Under Development</div>
          <div className="summary-subtext">
            Network asset auto-discovery pending
          </div>
        </div>
        <div className="summary-icon-box">
          <Network size={18} />
        </div>
      </div>
    </div>
  );
}
