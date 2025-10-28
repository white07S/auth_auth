import { useAuth } from '../components/auth/auth';

export default function Home() {
  const { user, roles } = useAuth();

  return (
    <div className="app-card">
      <h2>Welcome</h2>
      <p>You are signed in as {user?.display_name ?? 'Unknown User'}.</p>
      <div className="app-card-section">
        <h3>Roles</h3>
        {roles?.length ? (
          <ul>
            {roles.map((role) => (
              <li key={role}>{role}</li>
            ))}
          </ul>
        ) : (
          <p>No roles assigned.</p>
        )}
      </div>
    </div>
  );
}
