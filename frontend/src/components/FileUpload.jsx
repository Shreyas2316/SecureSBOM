import React, { useState } from 'react';
import { Upload, FileText, Search, Sparkles, AlertCircle } from 'lucide-react';

const SAMPLE_VULNERABLE_FIXTURE = `# SecureSBOM Controlled Demo Test Fixture
requests==2.25.1
urllib3==1.26.4
jinja2==2.11.2
flask==1.1.2
pyyaml==5.3.1
`;

export default function FileUpload({ onScanSubmit, isLoading, error }) {
  const [projectName, setProjectName] = useState('Demo Vulnerable App');
  const [requirementsContent, setRequirementsContent] = useState(SAMPLE_VULNERABLE_FIXTURE);

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setRequirementsContent(event.target.result);
      };
      reader.readAsText(file);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!requirementsContent.trim()) return;
    onScanSubmit(projectName, requirementsContent);
  };

  const loadSampleFixture = () => {
    setProjectName('Controlled Test Fixture (Outdated Packages)');
    setRequirementsContent(SAMPLE_VULNERABLE_FIXTURE);
  };

  return (
    <div className="glass-panel glow-hover" style={{ padding: '2rem', marginBottom: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', marginBottom: '0.25rem' }}>Dependency Analysis & SBOM Generator</h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
            Upload or paste Python <code style={{ color: 'var(--accent-cyan)' }}>requirements.txt</code> to initiate static dependency resolution and OSV/NVD vulnerability correlation.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={loadSampleFixture}
          style={{ fontSize: '0.8rem' }}
        >
          <Sparkles size={14} color="var(--accent-purple)" />
          Load Demo Fixture
        </button>
      </div>

      {error && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '8px',
          padding: '0.75rem 1rem',
          marginBottom: '1.5rem',
          color: '#fca5a5',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.875rem'
        }}>
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '1.25rem' }}>
          <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '0.5rem', color: 'var(--text-main)' }}>
            Project Name
          </label>
          <input
            type="text"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            required
            placeholder="e.g. My Web Application"
            style={{
              width: '100%',
              padding: '0.65rem 1rem',
              background: '#030712',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              color: '#ffffff',
              fontSize: '0.9rem',
              outline: 'none'
            }}
          />
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <label style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>
              Requirements Manifest (<code style={{ color: 'var(--accent-cyan)' }}>requirements.txt</code>)
            </label>
            <label className="btn btn-secondary" style={{ padding: '0.3rem 0.75rem', fontSize: '0.8rem', cursor: 'pointer' }}>
              <Upload size={14} />
              Upload File
              <input type="file" accept=".txt" onChange={handleFileUpload} style={{ display: 'none' }} />
            </label>
          </div>

          <textarea
            value={requirementsContent}
            onChange={(e) => setRequirementsContent(e.target.value)}
            rows={6}
            placeholder="Paste requirements.txt lines here (e.g. requests==2.25.1)"
            style={{
              width: '100%',
              padding: '1rem',
              background: '#030712',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              color: '#38bdf8',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.875rem',
              outline: 'none',
              resize: 'vertical'
            }}
          />
        </div>

        <button
          type="submit"
          className="btn btn-primary"
          disabled={isLoading}
          style={{ width: '100%', padding: '0.85rem', fontSize: '1rem' }}
        >
          {isLoading ? (
            <>
              <Search size={18} className="animate-spin" />
              Scanning Dependencies & Querying OSV/NVD APIs...
            </>
          ) : (
            <>
              <Search size={18} />
              Execute SecureSBOM Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
}
