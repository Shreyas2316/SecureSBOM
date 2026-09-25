import React from 'react';
import { ShieldAlert, History, FileCode2, Play } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, health }) {
  return (
    <header className="glass-panel" style={{ borderRadius: 0, borderTop: 0, borderLeft: 0, borderRight: 0, padding: '1rem 2rem', marginBottom: '2rem' }}>
      <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)', padding: '0.5rem', borderRadius: '8px', display: 'flex' }}>
            <ShieldAlert size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.03em' }}>
              Secure<span style={{ color: 'var(--accent-cyan)' }}>SBOM</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Software Supply Chain Dependency Scanner
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className={`btn ${activeTab === 'scan' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('scan')}
          >
            <Play size={16} />
            New Scan
          </button>
          
          <button
            className={`btn ${activeTab === 'history' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('history')}
          >
            <History size={16} />
            Scan History
          </button>

          <button
            className={`btn ${activeTab === 'sbom' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('sbom')}
          >
            <FileCode2 size={16} />
            CycloneDX SBOM
          </button>
        </nav>

        {/* Health status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: health?.status === 'healthy' ? '#22c55e' : '#ef4444',
            display: 'inline-block'
          }} />
          <span>API: {health?.status || 'connecting...'}</span>
        </div>

      </div>
    </header>
  );
}
