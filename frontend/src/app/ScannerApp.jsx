import React, { useState, useEffect } from "react";
import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";
import DashboardView from "../components/DashboardView";
import NewScanView from "../components/NewScanView";
import ScanResultsView from "../components/ScanResultsView";
import VulnDetailModal from "../components/VulnDetailModal";
import DependencyInventoryView from "../components/DependencyInventoryView";
import ScanHistoryView from "../components/ScanHistoryView";
import AIEmergingVulnView from "../components/AIEmergingVulnView";
import SaferAlternativesView from "../components/SaferAlternativesView";
import ReportsView from "../components/ReportsView";
import MonitoringStatusView from "../components/MonitoringStatusView";
import { fetchScanById, fetchScanHistory } from "../api";
import { CheckCircle2, AlertCircle, Info } from "lucide-react";

export default function ScannerApp() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [activeScan, setActiveScan] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [toasts, setToasts] = useState([]);

  const addToast = (message, type = "info") => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  };

  // Load the most recent scan on startup if exists
  useEffect(() => {
    fetchScanHistory(1)
      .then((data) => {
        if (data.scans && data.scans.length > 0) {
          const latestId = data.scans[0].id || data.scans[0].scan_id;
          if (latestId) {
            fetchScanById(latestId)
              .then((report) => setActiveScan({ report }))
              .catch(() => {});
          }
        }
      })
      .catch(() => {});
  }, []);

  const handleScanComplete = (scanResponse) => {
    setActiveScan(scanResponse);
    setActiveTab("results");
    const count = scanResponse.report?.summary?.total_canonical_vulnerabilities
      || scanResponse.summary?.unique_vuln_count
      || scanResponse.summary?.vuln_count
      || scanResponse.vulnerabilities?.length
      || 0;
    addToast(
      `Scan completed successfully! ${count} canonical vulnerabilities discovered.`,
      "success"
    );
  };

  const handleSelectScanById = async (scanId) => {
    try {
      const report = await fetchScanById(scanId);
      setActiveScan({ report });
      setActiveTab("results");
      const name = report.manifest_name || report.project_name || report.summary?.project_name || "Python Project";
      addToast(`Loaded scan session '${name}'`, "info");
    } catch (err) {
      addToast(err.message || "Failed to load scan details", "error");
    }
  };

  return (
    <div className="app-container">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        lastScanAvailable={Boolean(activeScan)}
      />

      <div className="main-wrapper">
        <Navbar
          activeTab={activeTab}
          onUserChange={() => {
            addToast("Tenant user context switched", "info");
            fetchScanHistory(1).then((data) => {
              if (data.scans && data.scans.length > 0) {
                const latestId = data.scans[0].id || data.scans[0].scan_id;
                if (latestId) {
                  fetchScanById(latestId).then((rep) => setActiveScan({ report: rep })).catch(() => {});
                }
              } else {
                setActiveScan(null);
              }
            });
          }}
        />

        <main className="content-area">
          {activeTab === "dashboard" && (
            <DashboardView
              onNavigate={setActiveTab}
              onSelectScan={handleSelectScanById}
              latestScan={activeScan}
            />
          )}

          {activeTab === "new_scan" && (
            <NewScanView onScanComplete={handleScanComplete} />
          )}

          {activeTab === "results" && (
            <ScanResultsView
              scanData={activeScan}
              onOpenVulnDetail={setSelectedVuln}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === "inventory" && (
            <DependencyInventoryView
              scanData={activeScan}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === "ai_vulns" && (
            <AIEmergingVulnView onNavigate={setActiveTab} />
          )}

          {activeTab === "alternatives" && (
            <SaferAlternativesView activeScan={activeScan} />
          )}

          {activeTab === "reports" && (
            <ReportsView activeScan={activeScan} />
          )}

          {activeTab === "history" && (
            <ScanHistoryView
              onSelectScan={handleSelectScanById}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === "monitoring" && (
            <MonitoringStatusView />
          )}
        </main>
      </div>

      {/* Vulnerability Details Modal */}
      {selectedVuln && (
        <VulnDetailModal
          vuln={selectedVuln}
          onClose={() => setSelectedVuln(null)}
        />
      )}

      {/* Global Toast Notifications */}
      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className="toast">
            {t.type === "success" && <CheckCircle2 size={18} style={{ color: "#00FF88" }} />}
            {t.type === "error" && <AlertCircle size={18} style={{ color: "#FF2E4D" }} />}
            {t.type === "info" && <Info size={18} style={{ color: "#00F5FF" }} />}
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
