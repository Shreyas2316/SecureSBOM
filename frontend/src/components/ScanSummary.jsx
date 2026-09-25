import React from 'react';
import { Package, ShieldAlert, Clock, Layers, AlertTriangle, FileText, AlertCircle } from 'lucide-react';

export default function ScanSummary({ summary }) {
  if (!summary) return null;

  const uniqueVulns = summary.unique_vuln_count ?? summary.vuln_count;
  const advisoryRecords = summary.advisory_record_count ?? summary.vuln_count;
  const affectedComponents = summary.affected_components_count ?? 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
      
      {/* Overview Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '1rem' }}>
        
        {/* Total Components Card */}
        <div className="glass-panel glow-hover" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Total Components</span>
            <Package size={18} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff' }}>
            {summary.total_deps}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'flex', gap: '0.75rem' }}>
            <span>Direct: <strong style={{ color: '#ffffff' }}>{summary.direct_deps}</strong></span>
            <span>Transitive: <strong style={{ color: 'var(--accent-purple)' }}>{summary.transitive_deps}</strong></span>
          </div>
        </div>

        {/* Unique Vulnerabilities Card */}
        <div className="glass-panel glow-hover" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Unique Vulnerabilities</span>
            <ShieldAlert size={18} color={uniqueVulns > 0 ? '#ef4444' : '#22c55e'} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: uniqueVulns > 0 ? '#fca5a5' : '#86efac' }}>
            {uniqueVulns}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Canonical findings after alias dedup
          </div>
        </div>

        {/* Advisory Records Card */}
        <div className="glass-panel glow-hover" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Advisory Records</span>
            <FileText size={18} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#ffffff' }}>
            {advisoryRecords}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Raw OSV/NVD source advisories
          </div>
        </div>

        {/* Affected Components Card */}
        <div className="glass-panel glow-hover" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            <span>Affected Components</span>
            <AlertCircle size={18} color={affectedComponents > 0 ? '#f97316' : '#22c55e'} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: affectedComponents > 0 ? '#fdba74' : '#86efac' }}>
            {affectedComponents}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Packages with ≥1 vulnerability
          </div>
        </div>

      </div>

      {/* Severity Breakdown Bar */}
      <div className="glass-panel" style={{ padding: '1.25rem' }}>
        <div style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Layers size={16} color="var(--accent-cyan)" />
          Severity Distribution (Unique Vulnerabilities)
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
          <span className="badge badge-critical">Critical: {summary.critical_count}</span>
          <span className="badge badge-high">High: {summary.high_count}</span>
          <span className="badge badge-medium">Medium: {summary.medium_count}</span>
          <span className="badge badge-low">Low: {summary.low_count}</span>
          <span className="badge badge-info">Info: {summary.info_count ?? 0}</span>
          <span className="badge" style={{ background: 'rgba(107, 114, 128, 0.2)', color: '#9ca3af', border: '1px solid rgba(107, 114, 128, 0.4)' }}>
            Unknown: {summary.unknown_count}
          </span>
        </div>
      </div>

      {/* Academic Disclaimer Banner */}
      <div style={{
        background: 'rgba(30, 41, 59, 0.6)',
        border: '1px solid rgba(148, 163, 184, 0.2)',
        borderRadius: '8px',
        padding: '0.85rem 1.25rem',
        fontSize: '0.8rem',
        color: '#94a3b8',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '0.75rem'
      }}>
        <AlertTriangle size={18} color="#e2e8f0" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong style={{ color: '#f1f5f9' }}>Academic Prototype Scope & Limitations:</strong> SecureSBOM correlates declared component versions against public OSV and NVD database records. A vulnerability match indicates a known CVE association in the component version but does not guarantee exploitability in application code. No zero-day prediction or reachability analysis is performed.
        </div>
      </div>

    </div>
  );
}
