import React from 'react';
import { Shield, LogOut } from 'lucide-react';

export default function Header({ user, onLogout }) {
  return (
    <header className="dashboard-header">
      <div className="header-brand">
        <Shield size={20} style={{ color: 'var(--color-primary)' }} />
        <h1>Quantum-Safe Forensics</h1>
      </div>
      <div className="header-meta">
        <div className="user-profile">
          <div className="user-info">
            <div className="user-name">{user.username}</div>
            <div className="user-role">{user.role}</div>
          </div>
          
          <button onClick={onLogout} className="logout-btn">
            <LogOut size={12} />
            <span>Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
}
