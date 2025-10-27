import React from 'react';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import Editor from './pages/Editor';
import Admin from './pages/Admin';
import Login from './Login';
import LoggedOut from './LoggedOut';

const routes = [
  { path: '/', element: <Landing />, label: 'Home' },
  { path: '/login', element: <Login />, publicOnly: true },
  { path: '/logged-out', element: <LoggedOut />, publicOnly: true },
  { path: '/dashboard', element: <Dashboard />, requiredPermissions: ['content:view'], label: 'Dashboard' },
  { path: '/editor', element: <Editor />, requiredPermissions: ['content:update'], label: 'Editor' },
  { path: '/admin', element: <Admin />, requiredPermissions: ['*'], label: 'Admin' },
];

export const navigationRoutes = routes.filter((route) => route.label);

export default routes;

