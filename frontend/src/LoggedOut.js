import React from 'react';
import { useAuth } from './components/auth/auth';

const LoggedOut = () => {
  const { login } = useAuth();
  const redirectTarget = typeof window !== 'undefined' ? window.location.hash || '#/' : '#/';

  return (
    <section className="page-centered">
      <h1>You are signed out</h1>
      <p>Your session is no longer active. Sign in again to continue.</p>
      <button type="button" className="primary" onClick={() => login(redirectTarget)}>
        Sign in
      </button>
    </section>
  );
};

export default LoggedOut;

