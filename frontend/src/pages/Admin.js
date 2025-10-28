import { useEffect, useState } from 'react';

import { apiFetch } from '../components/auth/api_auth';
import { useAuth } from '../components/auth/auth';

export default function Admin() {
  const { roles } = useAuth();
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    async function loadSummary() {
      try {
        const data = await apiFetch('/api/admin/summary');
        if (!cancelled) {
          setSummary(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message ?? 'Unable to load summary');
        }
      }
    }
    loadSummary();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="app-card">
      <h2>Admin Area</h2>
      <p>You currently have roles: {roles.join(', ') || 'none'}.</p>
      {error && <p className="app-error">{error}</p>}
      {summary && (
        <pre className="app-code-block">{JSON.stringify(summary, null, 2)}</pre>
      )}
    </div>
  );
}
