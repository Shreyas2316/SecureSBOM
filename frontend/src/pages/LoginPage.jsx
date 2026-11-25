import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { ShieldCheck, Lock, Mail, User, ArrowRight, AlertCircle } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const { login, register } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      if (mode === "login") {
        await login(username || email, password);
      } else {
        await register(username, email, password);
      }
      navigate("/app", { replace: true });
    } catch (err) {
      setError(err.message || "Authentication failed.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#05070A",
      color: "#F8FAFC",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: "1.5rem",
    }}>
      <div className="glass-panel" style={{
        width: "100%",
        maxWidth: "420px",
        padding: "2rem",
        border: "1px solid rgba(0, 245, 255, 0.25)",
        borderRadius: "12px",
        background: "#0B0E14",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "1.5rem" }}>
          <div style={{
            width: "40px",
            height: "40px",
            borderRadius: "10px",
            background: "linear-gradient(135deg, #00F5FF, #2563EB)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#05070A",
          }}>
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 style={{ fontSize: "1.25rem", fontWeight: 700, margin: 0 }}>SecureSBOM</h1>
            <span style={{ fontSize: "0.75rem", color: "#00F5FF", fontFamily: "var(--font-mono)" }}>
              AUTHENTICATED SECURITY CONSOLE
            </span>
          </div>
        </div>

        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.5rem" }}>
          <button
            type="button"
            className={`btn ${mode === "login" ? "btn-primary" : "btn-secondary"}`}
            style={{ flex: 1 }}
            onClick={() => { setMode("login"); setError(""); }}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`btn ${mode === "register" ? "btn-primary" : "btn-secondary"}`}
            style={{ flex: 1 }}
            onClick={() => { setMode("register"); setError(""); }}
          >
            Register
          </button>
        </div>

        {error && (
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            padding: "0.75rem",
            marginBottom: "1rem",
            borderRadius: "8px",
            background: "rgba(255, 46, 77, 0.12)",
            border: "1px solid rgba(255, 46, 77, 0.4)",
            color: "#FF6B81",
            fontSize: "0.85rem",
          }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.8rem", color: "#94A3B8", marginBottom: "6px" }}>
              {mode === "login" ? "Username or Email" : "Username"}
            </label>
            <div style={{ position: "relative" }}>
              <User size={15} style={{ position: "absolute", left: "12px", top: "12px", color: "#64748B" }} />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={mode === "login" ? "analyst or analyst@org.com" : "security_analyst"}
                className="input"
                style={{ width: "100%", paddingLeft: "36px" }}
              />
            </div>
          </div>

          {mode === "register" && (
            <div>
              <label style={{ display: "block", fontSize: "0.8rem", color: "#94A3B8", marginBottom: "6px" }}>
                Email Address
              </label>
              <div style={{ position: "relative" }}>
                <Mail size={15} style={{ position: "absolute", left: "12px", top: "12px", color: "#64748B" }} />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@organization.com"
                  className="input"
                  style={{ width: "100%", paddingLeft: "36px" }}
                />
              </div>
            </div>
          )}

          <div>
            <label style={{ display: "block", fontSize: "0.8rem", color: "#94A3B8", marginBottom: "6px" }}>
              Password {mode === "register" && "(min 8 characters)"}
            </label>
            <div style={{ position: "relative" }}>
              <Lock size={15} style={{ position: "absolute", left: "12px", top: "12px", color: "#64748B" }} />
              <input
                type="password"
                required
                minLength={mode === "register" ? 8 : 1}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="input"
                style={{ width: "100%", paddingLeft: "36px" }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "0.5rem", display: "flex", justifyContent: "center", gap: "8px" }}
          >
            <span>{submitting ? "Authenticating..." : mode === "login" ? "Sign In to Console" : "Create Account"}</span>
            <ArrowRight size={16} />
          </button>
        </form>

        <div style={{ marginTop: "1.25rem", textAlign: "center", fontSize: "0.8rem" }}>
          <Link to="/" style={{ color: "#94A3B8", textDecoration: "none" }}>
            ← Back to SecureSBOM Overview
          </Link>
        </div>
      </div>
    </div>
  );
}
