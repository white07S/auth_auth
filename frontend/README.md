# React BFF Frontend Starter

Single Page Application that pairs with the FastAPI backend to deliver an auth-safe BFF experience. The browser never sees tokens and only communicates with the backend over secure, cookie-authenticated requests.

## Key pieces

- `AuthProvider` (in `src/components/auth/auth.js`) bootstraps session state from `/auth/session`, exposes login/logout helpers, and wraps routed content.
- `ProtectedRoute` gates all authenticated routes and enforces optional role requirements.
- `api_auth.js` centralises fetch calls so credentials and CSRF headers are applied consistently.
- Example pages (`Home`, `Admin`, `Login`, `LoggedOut`) illustrate how to add routes with and without RBAC policies.

## Running locally

```bash
cd frontend
npm install   # installs CRA deps plus react-router-dom
npm start
```

The app uses a `HashRouter` so it can be hosted from static storage/CDNs without server rewrites. `REACT_APP_API_BASE` can be set to point at the backend if you serve them from different origins during development.

## Adding a secured page

1. Create a component under `src/pages/YourPage.js`.
2. Wrap the route with `ProtectedRoute` in `src/App.js` and pass any required roles.
3. Map the hash route to roles in `config.yaml.rbac.route_policies` on the backend.

## Testing

- `npm test` runs the default CRA test runner.
- The included example test stubs the `/auth/session` API so rendering stays deterministic.
