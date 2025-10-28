import { useEffect, useRef } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./components/auth/auth";

const normalizePath = (pathname) => {
  if (!pathname || pathname === "") {
    return "/";
  }
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname;
};

const ProtectedRoute = ({ children }) => {
  const location = useLocation();
  const { isLoading, isAuthenticated, allowedRoutes, refreshSession } = useAuth();
  const currentPath = normalizePath(location.pathname);
  const initialLoadRef = useRef(true);

  useEffect(() => {
    if (initialLoadRef.current) {
      initialLoadRef.current = false;
      return;
    }
    refreshSession();
  }, [refreshSession, currentPath]);

  if (isLoading) {
    return <div className="page page--loading">Loading session…</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoutes.length && !allowedRoutes.includes(currentPath)) {
    return <div className="page page--denied">Not authorized to view this page.</div>;
  }

  return children;
};

export default ProtectedRoute;
