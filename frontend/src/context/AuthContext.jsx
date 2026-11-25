import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import {
  fetchCurrentUser,
  loginUser,
  registerUser,
  logoutUser,
  getAccessToken,
  clearTokens,
} from "../api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadUser = useCallback(async () => {
    const token = getAccessToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const u = await fetchCurrentUser();
      setUser(u);
    } catch {
      clearTokens();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  const login = async (usernameOrEmail, password) => {
    const data = await loginUser({ usernameOrEmail, password });
    setUser(data.user);
    return data.user;
  };

  const register = async (username, email, password) => {
    const data = await registerUser({ username, email, password });
    setUser(data.user);
    return data.user;
  };

  const logout = async () => {
    await logoutUser();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser: loadUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
