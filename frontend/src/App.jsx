import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import FileUpload from './components/FileUpload';
import ScanSummary from './components/ScanSummary';
import VulnerabilityTable from './components/VulnerabilityTable';
import VulnerabilityDetailModal from './components/VulnerabilityDetailModal';
import SbomViewer from './components/SbomViewer';
import ScanHistory from './components/ScanHistory';
import { checkHealth, startScan, fetchScanHistory, fetchScanDetails, fetchScanSbom } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scan');
  const [health, setHealth] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const [currentScan, setCurrentScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [sbomData, setSbomData] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);

  useEffect(() => {
    // Initial health check & history fetch
    checkHealth().then(setHealth);
    loadHistory();
  }, []);

  const loadHistory = async () => {
    try {
      const data = await fetchScanHistory();
      setHistory(data);
    } catch (err) {
      console.warn("Could not load scan history", err);
    }
  };

  const handleScanSubmit = async (projectName, requirementsContent) => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await startScan(projectName, requirementsContent);
      setCurrentScan(result);
      
      // Load SBOM for this scan
      if (result.summary?.scan_id) {
        const sbom = await fetchScanSbom(result.summary.scan_id);
        setSbomData(sbom);
      }

      await loadHistory();
      setActiveTab('scan');
    } catch (err) {
      setError(err.message || 'An error occurred during scanning');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectScan = async (scanId) => {
    setIsLoading(true);
    setError(null);
    try {
      const details = await fetchScanDetails(scanId);
      setCurrentScan(details);

      const sbom = await fetchScanSbom(scanId);
      setSbomData(sbom);

      setActiveTab('scan');
    } catch (err) {
      setError(`Failed to load scan #${scanId}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} health={health} />

      <main style={{ flex: 1, maxWidth: '1280px', width: '100%', margin: '0 auto', padding: '0 1.5rem 3rem' }}>
        
        {activeTab === 'scan' && (
          <div>
            <FileUpload onScanSubmit={handleScanSubmit} isLoading={isLoading} error={error} />
            
            {currentScan && (
              <>
                <ScanSummary summary={currentScan.summary} />
                <VulnerabilityTable
                  vulnerabilities={currentScan.vulnerabilities}
                  onSelectVuln={setSelectedVuln}
                />
              </>
            )}
          </div>
        )}

        {activeTab === 'history' && (
          <ScanHistory history={history} onSelectScan={handleSelectScan} />
        )}

        {activeTab === 'sbom' && (
          <SbomViewer sbomData={sbomData} components={currentScan?.components || []} />
        )}

      </main>

      {selectedVuln && (
        <VulnerabilityDetailModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />
      )}

      {/* Footer */}
      <footer style={{
        textAlign: 'center',
        padding: '1.5rem',
        borderTop: '1px solid var(--border-color)',
        color: 'var(--text-dim)',
        fontSize: '0.8rem'
      }}>
        SecureSBOM — Academic Prototype (PRJ_56) | Student Scale | Free/OSS Public APIs (OSV & NVD)
      </footer>
    </div>
  );
}
