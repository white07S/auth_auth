import React from 'react';
import { useAuth } from '../components/auth/auth';

const Dashboard = () => {
  const { user, roles, permissions, idleRemainingSec } = useAuth();

  return (
    <section className="page">
      <h1>Dashboard</h1>
      <p>Welcome back, {user?.displayName || user?.email}.</p>
      <div className="card">
        <h2>Session</h2>
        <ul>
          <li>
            <strong>Email:</strong> {user?.email || 'unknown'}
          </li>
          <li>
            <strong>Roles:</strong> {roles.join(', ') || 'none'}
          </li>
          <li>
            <strong>Permissions:</strong> {permissions.join(', ') || 'none'}
          </li>
          <li>
            <strong>Idle remaining:</strong> {idleRemainingSec != null ? `${idleRemainingSec} seconds` : 'n/a'}
          </li>
        </ul>
      </div>
    </section>
  );
};

export default Dashboard;

