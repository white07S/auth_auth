import React from 'react';
import { Link, NavLink } from 'react-router-dom';
import { useAuth } from './components/auth/auth';
import { navigationRoutes } from './routes';

const Header = () => {
  const { authenticated, user, permissions, login, logout } = useAuth();
  const safePermissions = permissions || [];

  const canSee = (item) => {
    if (!item.requiredPermissions || item.requiredPermissions.length === 0) {
      return true;
    }
    if (safePermissions.includes('*')) {
      return true;
    }
    return item.requiredPermissions.every((perm) => safePermissions.includes(perm) || perm === '*');
  };

  const authAction = authenticated ? (
    <>
      <span className="app-user">{user?.displayName || user?.email}</span>
      <button type="button" className="linklike" onClick={logout}>
        Sign out
      </button>
    </>
  ) : (
    <button type="button" className="primary" onClick={() => login()}>
      Sign in
    </button>
  );

  return (
    <header className="app-header">
      <Link to="/" className="brand">
        Auth BFF
      </Link>
      <nav className="app-nav">
        {navigationRoutes.filter(canSee).map((item) => (
          <NavLink key={item.path} to={item.path} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="app-auth">{authAction}</div>
    </header>
  );
};

export default Header;
