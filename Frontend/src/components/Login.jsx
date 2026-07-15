import React, { useState } from 'react';
import { Shield, User, Lock, KeyRound } from 'lucide-react';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('SOC Analyst');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Operator credentials cannot be empty.');
      return;
    }
    if (password.length < 4) {
      setError('Password must be at least 4 characters.');
      return;
    }
    setError('');
    onLogin({ username, role });
  };

  return (
    <div className="login-container">
      <div className="login-card panel">
        <div className="login-header">
          <Shield size={32} style={{ color: 'var(--color-primary)', margin: '0 auto' }} />
          <h1>Quantum-Safe Forensics</h1>
          <p>Operator Sign-In Mainframe Console</p>
        </div>

        <form onSubmit={handleSubmit}>
          {error && (
            <div 
              style={{
                background: 'var(--color-critical-light)',
                border: '1px solid var(--color-critical)',
                color: 'var(--color-critical)',
                padding: '8px 12px',
                borderRadius: '4px',
                fontSize: '0.75rem',
                marginBottom: '14px',
                textAlign: 'left'
              }}
            >
              {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Operator Username</label>
            <div className="input-wrapper">
              <User className="input-icon" />
              <input
                id="username"
                type="text"
                className="form-input"
                placeholder="operator.id"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="password">Security Password</label>
            <div className="input-wrapper">
              <Lock className="input-icon" />
              <input
                id="password"
                type="password"
                className="form-input"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="role">Security Role Assignment</label>
            <div className="input-wrapper">
              <KeyRound className="input-icon" />
              <select
                id="role"
                className="form-input"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                style={{ appearance: 'none', cursor: 'pointer' }}
              >
                <option value="SOC Analyst">SOC Analyst</option>
                <option value="Security Administrator">Security Administrator</option>
                <option value="Incident Responder">Incident Responder</option>
                <option value="Cryptographic Auditor">Cryptographic Auditor</option>
              </select>
              <div 
                style={{
                  position: 'absolute',
                  right: '12px',
                  pointerEvents: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '0.7rem'
                }}
              >
                ▼
              </div>
            </div>
          </div>

          <button type="submit" className="btn-primary">
            Sign In to Console
          </button>
        </form>
      </div>
    </div>
  );
}
