import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';

import { AuthProvider, ProtectedRoute } from './components/auth/auth';
import AccessDenied from './components/common/AccessDenied';
import Loading from './components/common/Loading';
import Header from './components/layout/Header';
import Admin from './pages/Admin';
import Home from './pages/Home';
import Login from './pages/Login';
import LoggedOut from './pages/LoggedOut';

import './App.css';

function App() {
  return (
    <AuthProvider>
      <HashRouter>
        <div className="app-shell">
          <Header />
          <main className="app-main">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/logged-out" element={<LoggedOut />} />
              <Route
                path="/home"
                element={
                  <ProtectedRoute fallback={<Loading message="Loading session…" />}>
                    <Home />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/admin"
                element={
                  <ProtectedRoute requiredRoles={["admin"]} fallback={<AccessDenied />}>
                    <Admin />
                  </ProtectedRoute>
                }
              />
              <Route path="/denied" element={<AccessDenied />} />
              <Route path="/" element={<Navigate to="/home" replace />} />
              <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
          </main>
        </div>
      </HashRouter>
    </AuthProvider>
  );
}

export default App;
