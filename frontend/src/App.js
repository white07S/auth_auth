import { HashRouter, Route, Routes } from "react-router-dom";
import "./App.css";
import Header from "./components/Header";
import { AuthProvider } from "./components/auth/auth";
import ProtectedRoute from "./ProtectedRoute";
import LoggedOut from "./LoggedOut";
import Login from "./Login";
import Home from "./pages/Home";
import Docs from "./pages/Docs";
import Scenario from "./pages/Scenario";
import Chat from "./pages/Chat";
import Task from "./pages/Task";
import Dashboard from "./pages/Dashboard";

const App = () => (
  <HashRouter>
    <AuthProvider>
      <div className="app-shell">
        <Header />
        <main className="app-main">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/logged-out" element={<LoggedOut />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Home />
                </ProtectedRoute>
              }
            />
            <Route
              path="/docs"
              element={
                <ProtectedRoute>
                  <Docs />
                </ProtectedRoute>
              }
            />
            <Route
              path="/scenario"
              element={
                <ProtectedRoute>
                  <Scenario />
                </ProtectedRoute>
              }
            />
            <Route
              path="/chat"
              element={
                <ProtectedRoute>
                  <Chat />
                </ProtectedRoute>
              }
            />
            <Route
              path="/task"
              element={
                <ProtectedRoute>
                  <Task />
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              }
            />
          </Routes>
        </main>
      </div>
    </AuthProvider>
  </HashRouter>
);

export default App;
