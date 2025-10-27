import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Header from './Header';
import routes from './routes';
import ProtectedRoute from './components/auth/ProtectedRoute';
import NotFound from './pages/NotFound';
import './App.css';

const App = () => (
  <div className="app-shell">
    <Header />
    <main className="app-main">
      <Routes>
        {routes.map((route) => {
          const element = route.requiredPermissions ? (
            <ProtectedRoute requiredPermissions={route.requiredPermissions}>{route.element}</ProtectedRoute>
          ) : (
            route.element
          );
          return <Route key={route.path} path={route.path} element={element} />;
        })}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </main>
  </div>
);

export default App;
