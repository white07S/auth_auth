import { Navigate } from "react-router-dom";
import { useAuth } from "./components/auth/auth";

const submitPost = (path) => {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = path;
  document.body.appendChild(form);
  form.submit();
};

const Login = () => {
  const { isAuthenticated, isLoading } = useAuth();

  if (!isLoading && isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const handleLogin = () => {
    submitPost("/auth/login");
  };

  return (
    <div className="page page--login">
      <h2>Sign in</h2>
      <p>Access requires a Microsoft Entra account with the appropriate role.</p>
      <button type="button" onClick={handleLogin}>
        Sign in with Microsoft
      </button>
    </div>
  );
};

export default Login;
