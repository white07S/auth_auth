import { useAuth } from "./auth/auth";

const submitPost = (path) => {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = path;
  document.body.appendChild(form);
  form.submit();
};

const Header = () => {
  const { isAuthenticated, user } = useAuth();

  const handleLogout = () => {
    submitPost("/auth/logout");
  };

  return (
    <header className="app-header">
      <div className="app-brand">Auth Portal</div>
      <div className="app-actions">
        {isAuthenticated ? (
          <>
            <span className="app-user">
              {user?.name}
              {user?.email ? ` (${user.email})` : ""}
            </span>
            <button type="button" onClick={handleLogout}>
              Logout
            </button>
          </>
        ) : (
          <a href="#/login">Login</a>
        )}
      </div>
    </header>
  );
};

export default Header;
