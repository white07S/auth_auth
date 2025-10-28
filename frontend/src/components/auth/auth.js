import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { request } from "./api_auth";

const CSRF_CONFIG = {
  cookieName: "bff_csrf",
  headerName: "x-csrf-token",
};

const AuthContext = createContext({
  isLoading: true,
  isAuthenticated: false,
  user: null,
  roles: [],
  allowedRoutes: [],
  refreshSession: async () => {},
});

const AuthProvider = ({ children }) => {
  const [authState, setAuthState] = useState({
    isLoading: true,
    isAuthenticated: false,
    user: null,
    roles: [],
    allowedRoutes: [],
    expiresAt: null,
    tokenExpiresAt: null,
  });

  const loadSession = useCallback(async () => {
    setAuthState((previous) => ({
      ...previous,
      isLoading: true,
    }));
    try {
      const data = await request("/auth/session", { method: "GET" }, CSRF_CONFIG);
      setAuthState({
        isLoading: false,
        isAuthenticated: true,
        user: data.user,
        roles: data.roles || [],
        allowedRoutes: data.allowed_routes || [],
        expiresAt: data.expires_at,
        tokenExpiresAt: data.token_expires_at,
      });
    } catch (error) {
      setAuthState({
        isLoading: false,
        isAuthenticated: false,
        user: null,
        roles: [],
        allowedRoutes: [],
        expiresAt: null,
        tokenExpiresAt: null,
      });
    }
  }, []);

  useEffect(() => {
    loadSession();
  }, [loadSession]);

  const value = useMemo(
    () => ({
      ...authState,
      refreshSession: loadSession,
    }),
    [authState, loadSession],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

const useAuth = () => useContext(AuthContext);

export { AuthContext, AuthProvider, useAuth, CSRF_CONFIG };
