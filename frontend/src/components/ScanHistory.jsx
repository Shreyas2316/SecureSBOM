import React from 'react';
import { History, ArrowRight, ShieldAlert, Package, Calendar } from 'lucide-react';

export default function ScanHistory({ history, onSelectScan }) {
  if (!history || history.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        <History size={36} color="var(--accent-purple)" style={{ margin: '0 auto 1rem display: block' }} />
        <h3 style={{ color: '#ffffff', marginBottom: '0.5rem' }}>No Scan History Recorded</h3>
        <p style={{ fontSize: '0.875rem' }}>Completed scans will automatically persist in PostgreSQL / database storage.</p>
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
      <div style={{ marginBottom: '1.25rem' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <History size={20} color="var(--accent-purple)" />
          Scan History
        </h3>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          Persisted scan records stored in database
        </p>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              <th style={{ padding: '0.75rem 1rem' }}>Scan ID</th>
              <th style={{ padding: '0.75rem 1rem' }}>Project Name</th>
              <th style={{ padding: '0.75rem 1rem' }}>Timestamp</th>
              <th style={{ padding: '0.75rem 1rem' }}>Dependencies</th>
              <th style={{ padding: '0.75rem 1rem' }}>Vulnerabilities</th>
              <th style={{ padding: '0.75rem 1rem' }}>Critical / High</th>
              <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {history.map((scan) => (
              <tr key={scan.scan_id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                  #{scan.scan_id}
                </td>

                <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#ffffff' }}>
                  {scan.project_name}
                </td>

                <td style={{ padding: '0.75rem 1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  {new Date(scan.timestamp).toLocaleString()}
                </td>

                <td style={{ padding: '0.75rem 1rem' }}>
                  {scan.total_deps}
                </td>

                <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: scan.vuln_count > 0 ? '#fca5a5' : '#86efac' }}>
                  {scan.vuln_count}
                </td>

                <td style={{ padding: '0.75rem 1rem' }}>
                  <span className="badge badge-critical">{scan.critical_count}</span>
                  <span className="badge badge-high" style={{ marginLeft: '0.25rem' }}>{scan.high_count}</span>
                </td>

                <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                  <button
                    className="btn btn-secondary"
                    onClick={() => onSelectScan(scan.scan_id)}
                    style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem' }}
                  >
                    View Results
                    <ArrowRight size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
