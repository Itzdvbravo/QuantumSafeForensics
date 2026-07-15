import React, { useState, useEffect } from 'react';
import { ChevronRight } from 'lucide-react';
import Login from './components/Login';
import Header from './components/Header';
import DashboardSummaries from './components/DashboardSummaries';
import AlertNavigation from './components/AlertNavigation';
import AlertDetail from './components/AlertDetail';

export default function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [fetchError, setFetchError] = useState(null);
  // Per-alert detail cache: { [alertId]: { historicActions, assetsAndUsers } }
  const [detailCache, setDetailCache] = useState({});
  const [detailLoading, setDetailLoading] = useState(false);

  const loadAlerts = () => {
    setFetchError(null);
    return fetch('/api/alerts')
      .then(response => {
        if (!response.ok) throw new Error(`Server responded with ${response.status}`);
        return response.json();
      })
      .then(data => {
        const sortedData = [...data].sort((a, b) => (b.riskPercentage || 0) - (a.riskPercentage || 0));
        setAlerts(sortedData);
        setSelectedAlertId(sortedData[0]?.alertId ?? null);
        setIsLoading(false);
      })
      .catch(err => {
        console.error('API fetch error:', err);
        setFetchError(err.message);
        setIsLoading(false);
      });
  };

  // Authentication session persistence — re-fetch from API on restore
  useEffect(() => {
    const session = localStorage.getItem('quantum_forensics_session');
    if (session) {
      setCurrentUser(JSON.parse(session));
      setIsLoading(true);
    }
  }, []);

  const handleLogin = (userCredentials) => {
    setCurrentUser(userCredentials);
    localStorage.setItem('quantum_forensics_session', JSON.stringify(userCredentials));
    setIsLoading(true);
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setAlerts([]);
    setSelectedAlertId(null);
    setFetchError(null);
    setDetailCache({});
    localStorage.removeItem('quantum_forensics_session');
  };

  // Real API fetch on login / session restore
  useEffect(() => {
    if (!isLoading) return;
    loadAlerts();
  }, [isLoading]);

  // Fetch heavy details whenever the selected alert changes
  useEffect(() => {
    if (!selectedAlertId) return;
    // Already cached — skip
    if (detailCache[selectedAlertId]) return;

    setDetailLoading(true);
    fetch(`/api/alerts/${selectedAlertId}/details`)
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => {
        setDetailCache(prev => ({
          ...prev,
          [selectedAlertId]: {
            historicActions: data.historicActions ?? [],
            assetsAndUsers:  data.assetsAndUsers  ?? [],
          }
        }));
        setDetailLoading(false);
      })
      .catch(err => {
        console.warn('Detail fetch failed for', selectedAlertId, err);
        // Store empty so we don't keep retrying
        setDetailCache(prev => ({
          ...prev,
          [selectedAlertId]: { historicActions: [], assetsAndUsers: [] }
        }));
        setDetailLoading(false);
      });
  }, [selectedAlertId]);

  const baseAlert = alerts.find(a => a.alertId === selectedAlertId);
  const cachedDetail = detailCache[selectedAlertId];
  // Merge summary + details into one object for the detail panel
  const activeAlert = baseAlert
    ? { ...baseAlert, ...(cachedDetail ?? {}), detailLoading }
    : undefined;

  // 1. Initial State: Login Gateway
  if (!currentUser) {
    return <Login onLogin={handleLogin} />;
  }

  // 2. Loading state
  if (isLoading) {
    return (
      <div className="center-loader">
        <div className="spinner-icon"></div>
        <div className="loader-text">Connecting to forensics log engine...</div>
      </div>
    );
  }

  // 3. Error state — API unreachable
  if (fetchError) {
    return (
      <div className="center-loader">
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--color-critical)',
          borderRadius: '8px',
          padding: '32px 40px',
          maxWidth: '480px',
          textAlign: 'center'
        }}>
          <div style={{ color: 'var(--color-critical)', fontSize: '2rem', marginBottom: '12px' }}>⚠</div>
          <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '8px', fontSize: '1rem' }}>
            Forensics Engine Unreachable
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', lineHeight: 1.6, marginBottom: '20px' }}>
            Failed to connect to forensics engine. Ensure the Python server is running on port 5000.
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)', background: 'var(--bg-deep)', borderRadius: '4px', padding: '8px 12px', marginBottom: '20px' }}>
            {fetchError}
          </div>
          <button
            onClick={() => { setIsLoading(true); }}
            style={{
              background: 'var(--color-primary)',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              padding: '8px 20px',
              cursor: 'pointer',
              fontWeight: 600,
              fontSize: '0.82rem'
            }}
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  // 4. Authenticated Dashboard Layout
  return (
    <div className="dashboard-layout">
      <Header user={currentUser} onLogout={handleLogout} />
      
      {/* Top dashboard metrics summaries */}
      <DashboardSummaries alerts={alerts} />

      {/* Main Workspace */}
      <main className="main-workspace">
        {!isSidebarCollapsed ? (
          <AlertNavigation 
            alerts={alerts} 
            selectedAlertId={selectedAlertId} 
            onSelectAlert={setSelectedAlertId} 
            onCollapse={() => setIsSidebarCollapsed(true)}
          />
        ) : (
          <button 
            onClick={() => setIsSidebarCollapsed(false)}
            className="panel"
            style={{
              width: '36px',
              height: 'calc(100vh - 160px)',
              minHeight: '480px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-secondary)',
              gap: '12px',
              borderRadius: '4px',
              flexShrink: 0
            }}
            title="Expand Incident List"
          >
            <ChevronRight size={14} />
            <span style={{ writingMode: 'vertical-lr', textTransform: 'uppercase', fontSize: '0.65rem', letterSpacing: '0.05em', fontWeight: 600 }}>
              Incidents
            </span>
          </button>
        )}
        <AlertDetail alert={activeAlert} />
      </main>
    </div>
  );
}
