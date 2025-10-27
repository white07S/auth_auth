import React from 'react';
import LoggedOut from '../../LoggedOut';
import { useAuth } from './auth';

const hasPermission = (permissions, required) => {
  if (!required || required.length === 0) {
    return true;
  }
  if (permissions.includes('*')) {
    return true;
  }
  return required.every((permission) => permissions.includes(permission));
};

const ProtectedRoute = ({ requiredPermissions = [], children }) => {
  const { status, authenticated, permissions, error } = useAuth();

  if (status === 'loading') {
    return (
      <div className="page-centered">
        <div className="spinner" />
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="page-centered">
        <p role="alert">We hit an auth issue: {error}</p>
      </div>
    );
  }

  if (!authenticated) {
    return <LoggedOut />;
  }

  if (!hasPermission(permissions, requiredPermissions)) {
    return (
      <div className="page-centered">
        <h2>Not authorized</h2>
        <p>You do not have permission to access this view.</p>
      </div>
    );
  }

  return children;
};

export default ProtectedRoute;

