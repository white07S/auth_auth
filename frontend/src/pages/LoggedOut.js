import { useAuth } from '../components/auth/auth';

export default function LoggedOut() {
  const { login } = useAuth();

  return (
    <div className="app-card">
      <h2>You have signed out</h2>
      <p>To continue, sign back in with your organisational account.</p>
      <button type="button" className="app-button" onClick={login}>
        Sign back in
      </button>
    </div>
  );
}
