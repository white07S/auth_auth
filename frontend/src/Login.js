import React from 'react';
import { useAuth } from './components/auth/auth';

const Login = () => {
  const { login } = useAuth();
  const redirectTarget = typeof window !== 'undefined' ? window.location.hash || '#/dashboard' : '#/dashboard';

  return (
    <section className="page-centered">
      <h1>Sign in</h1>
      <p>Use your Microsoft Azure AD account to continue.</p>
      <button type="button" className="primary" onClick={() => login(redirectTarget)}>
        Sign in with Microsoft
      </button>
    </section>
  );
};

export default Login;

