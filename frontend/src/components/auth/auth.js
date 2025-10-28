import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { apiFetch, getSession, logout as apiLogout, startLogin } from './api_auth';

const AuthContext = createContext(undefined);

const initialState = {
  isLoading: true,
  isAuthenticated: false,
  user: null,
  roles: [],
  expiresAt: null,
  error: null,
};

export function AuthProvider({ children }) {
  const [state, setState] = useState(initialState);

  const refreshSession = useCallback(async () => {
    setState((prev) => ({ ...prev, isLoading: true, error: null }));
    try {
      const session = await getSession();
      setState({
        isLoading: false,
        isAuthenticated: session.is_authenticated,
        user: session.user,
        roles: session.roles ?? [],
        expiresAt: session.expires_at ? new Date(session.expires_at) : null,
        error: null,
      });
    } catch (error) {
      setState({
        ...initialState,
        isLoading: false,
        error,
      });
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  const login = useCallback(async () => {
    const { authorization_url: authorizationUrl } = await startLogin();
    window.location.assign(authorizationUrl);
  }, []);

  const logout = useCallback(async () => {
    try {
      const response = await apiLogout();
      if (response.redirect_url) {
        window.location.assign(response.redirect_url);
        return;
      }
    } finally {
      await refreshSession();
    }
    window.location.hash = '#/login';
  }, [refreshSession]);

  const value = useMemo(
    () => ({
      ...state,
      login,
      logout,
      refreshSession,
      apiFetch,
    }),
    [state, login, logout, refreshSession]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

function hasRequiredRoles(requiredRoles, userRoles) {
  if (!requiredRoles || requiredRoles.length === 0) {
    return true;
  }
  if (!userRoles || userRoles.length === 0) {
    return false;
  }
  return requiredRoles.every((role) => userRoles.includes(role));
}

export function ProtectedRoute({ requiredRoles = [], fallback = null, children }) {
  const { isLoading, isAuthenticated, roles } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return fallback ?? <div className="app-loading">Loading…</div>;
  }
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  if (!hasRequiredRoles(requiredRoles, roles)) {
    return fallback ?? <div className="app-access-denied">Access denied</div>;
  }
  return children;
}

export default AuthContext;
