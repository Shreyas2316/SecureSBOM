import React, { useState } from "react";
import { Settings, KeyRound, ShieldCheck, CheckCircle2, AlertCircle } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { updateAICredentials, changePassword } from "../api";

export default function SettingsView() {
  const { user, refreshUser } = useAuth();
  const [aiKey, setAiKey] = useState("");
  const [consent, setConsent] = useState(Boolean(user?.ai_provider_consent));
  const [currPw, setCurrPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const handleSaveAI = async (e) => {
    e.preventDefault();
    setMsg("");
    setErr("");
    try {
      await updateAICredentials({ aiApiKey: aiKey || undefined, aiProviderConsent: consent });
      await refreshUser();
      setAiKey("");
      setMsg("Encrypted AI credential & consent preferences saved.");
    } catch (e2) {
      setErr(e2.message || "Failed to save AI credentials.");
    }
  };

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setMsg("");
    setErr("");
    try {
      await changePassword({ currentPassword: currPw, newPassword: newPw });
      setCurrPw("");
      setNewPw("");
      setMsg("Password updated successfully.");
    } catch (e2) {
      setErr(e2.message || "Failed to update password.");
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem", maxWidth: "760px" }}>
      <div className="glass-panel" style={{ padding: "1.5rem" }}>
        <h2 style={{ fontSize: "1.2rem", display: "flex", alignItems: "center", gap: "8px", margin: 0 }}>
          <Settings size={20} color="#00F5FF" />
          Account & Security Settings
        </h2>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginTop: "4px" }}>
          Signed in as <strong>{user?.username}</strong> ({user?.email}) · Role: <span style={{ color: "#00F5FF" }}>{user?.role}</span>
        </p>
      </div>

      {msg && (
        <div className="glass-panel" style={{ padding: "0.85rem 1rem", color: "#00FF88", display: "flex", alignItems: "center", gap: "8px" }}>
          <CheckCircle2 size={16} /> <span>{msg}</span>
        </div>
      )}
      {err && (
        <div className="glass-panel" style={{ padding: "0.85rem 1rem", color: "#FF6B81", display: "flex", alignItems: "center", gap: "8px" }}>
          <AlertCircle size={16} /> <span>{err}</span>
        </div>
      )}

      <form onSubmit={handleSaveAI} className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
        <h3 style={{ fontSize: "1rem", display: "flex", alignItems: "center", gap: "8px", margin: 0 }}>
          <ShieldCheck size={18} color="#00F5FF" />
          Encrypted AI Provider Credentials & Consent
        </h3>
        <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.85rem", cursor: "pointer" }}>
          <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          <span>I consent to sending sanitized package metadata/excerpts to the configured AI provider.</span>
        </label>
        <div>
          <label style={{ display: "block", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "6px" }}>
            Optional Personal AI API Key ({user?.has_custom_ai_key ? "Encrypted key stored" : "None stored"})
          </label>
          <input
            type="password"
            className="input"
            placeholder="Enter API key to encrypt at rest with MultiFernet"
            value={aiKey}
            onChange={(e) => setAiKey(e.target.value)}
            style={{ width: "100%" }}
          />
        </div>
        <button type="submit" className="btn btn-primary" style={{ alignSelf: "flex-start" }}>
          Save Encrypted Settings
        </button>
      </form>

      <form onSubmit={handlePasswordChange} className="glass-panel" style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
        <h3 style={{ fontSize: "1rem", display: "flex", alignItems: "center", gap: "8px", margin: 0 }}>
          <KeyRound size={18} color="#00F5FF" />
          Change Password (Argon2id)
        </h3>
        <input
          type="password"
          required
          className="input"
          placeholder="Current password"
          value={currPw}
          onChange={(e) => setCurrPw(e.target.value)}
        />
        <input
          type="password"
          required
          minLength={8}
          className="input"
          placeholder="New password (min 8 chars)"
          value={newPw}
          onChange={(e) => setNewPw(e.target.value)}
        />
        <button type="submit" className="btn btn-secondary" style={{ alignSelf: "flex-start" }}>
          Update Password
        </button>
      </form>
    </div>
  );
}
