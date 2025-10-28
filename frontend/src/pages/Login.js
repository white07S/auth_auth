import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../components/auth/auth';

export default function Login() {
  const { login, isLoading, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/home', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  return (
    <div className="app-card">
      <h2>Sign in with Entra ID</h2>
      <p>Use your organisation account to access the application.</p>
      <button type="button" className="app-button" onClick={login} disabled={isLoading}>
        {isLoading ? 'Preparing…' : 'Continue to Microsoft Login'}
      </button>
    </div>
  );
}
