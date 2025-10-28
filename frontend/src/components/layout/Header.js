import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/auth';

import './Header.css';

export default function Header() {
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="app-header">
      <div className="app-brand">
        <Link to="/home">Auth BFF Starter</Link>
      </div>
      <nav className="app-nav">
        {isAuthenticated && (
          <>
            <span className="app-user">{user?.display_name || 'Signed in'}</span>
            <button type="button" className="app-button" onClick={handleLogout}>
              Logout
            </button>
          </>
        )}
      </nav>
    </header>
  );
}
