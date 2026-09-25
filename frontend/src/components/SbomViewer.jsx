import React, { useState } from 'react';
import { Download, FileCode2, Code, Package, Copy, Check } from 'lucide-react';

export default function SbomViewer({ sbomData, components }) {
  const [activeView, setActiveView] = useState('tree');
  const [copied, setCopied] = useState(false);

  if (!sbomData && (!components || components.length === 0)) {
    return (
      <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        <FileCode2 size={36} color="var(--accent-cyan)" style={{ margin: '0 auto 1rem display: block' }} />
        <h3 style={{ color: '#ffffff', marginBottom: '0.5rem' }}>No SBOM Available</h3>
        <p style={{ fontSize: '0.875rem' }}>Run a scan to generate the CycloneDX 1.4 JSON SBOM standard document.</p>
      </div>
    );
  }

  const handleDownload = () => {
    const jsonStr = JSON.stringify(sbomData?.bom_json || {}, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'bom.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = () => {
    const jsonStr = JSON.stringify(sbomData?.bom_json || {}, null, 2);
    navigator.clipboard.writeText(jsonStr);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', marginBottom: '1.25rem' }}>
        <div>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <FileCode2 size={20} color="var(--accent-cyan)" />
            CycloneDX 1.4 Software Bill of Materials (SBOM)
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Compliant with OWASP CycloneDX JSON specification (output saved to <code style={{ color: 'var(--accent-cyan)' }}>output/bom.json</code>)
          </p>
        </div>

        {/* View Toggle & Download */}
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className={`btn ${activeView === 'tree' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveView('tree')}
            style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
          >
            <Package size={14} />
            Component List
          </button>
          
          <button
            className={`btn ${activeView === 'json' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveView('json')}
            style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
          >
            <Code size={14} />
            Raw JSON
          </button>

          <button
            className="btn btn-secondary"
            onClick={handleDownload}
            style={{ padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
          >
            <Download size={14} />
            Download bom.json
          </button>
        </div>
      </div>

      {/* Content View */}
      {activeView === 'tree' ? (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                <th style={{ padding: '0.75rem 1rem' }}>Component Name</th>
                <th style={{ padding: '0.75rem 1rem' }}>Version</th>
                <th style={{ padding: '0.75rem 1rem' }}>Type</th>
                <th style={{ padding: '0.75rem 1rem' }}>Package URL (PURL)</th>
                <th style={{ padding: '0.75rem 1rem' }}>Scope</th>
              </tr>
            </thead>
            <tbody>
              {components && components.map((c, idx) => (
                <tr key={c.id || idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#ffffff' }}>
                    {c.name}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)' }}>
                    v{c.version}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    library
                  </td>
                  <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}>
                    {c.purl}
                  </td>
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <span className={`badge ${c.is_direct ? 'badge-low' : 'badge-info'}`}>
                      {c.is_direct ? 'Direct' : `Transitive (Depth ${c.dependency_depth})`}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ position: 'relative' }}>
          <button
            onClick={handleCopy}
            className="btn btn-secondary"
            style={{ position: 'absolute', top: '0.75rem', right: '0.75rem', fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
          >
            {copied ? <Check size={14} color="#22c55e" /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy JSON'}
          </button>
          <pre style={{
            background: '#030712',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '1.25rem',
            color: '#38bdf8',
            fontSize: '0.8rem',
            fontFamily: 'var(--font-mono)',
            maxHeight: '500px',
            overflowY: 'auto'
          }}>
            {JSON.stringify(sbomData?.bom_json || {}, null, 2)}
          </pre>
        </div>
      )}

    </div>
  );
}
