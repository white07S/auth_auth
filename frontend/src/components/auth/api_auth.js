const API_BASE = process.env.REACT_APP_API_BASE ?? '';

const defaultOptions = {
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
  },
};

async function parseJson(response) {
  const text = await response.text();
  return text ? JSON.parse(text) : {};
}

async function handleResponse(response) {
  if (!response.ok) {
    const payload = await parseJson(response).catch(() => ({}));
    const error = new Error(payload.detail || response.statusText);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return parseJson(response);
}

export async function getSession() {
  const response = await fetch(`${API_BASE}/auth/session`, {
    ...defaultOptions,
    method: 'GET',
  });
  return handleResponse(response);
}

export async function startLogin() {
  const response = await fetch(`${API_BASE}/auth/login`, {
    ...defaultOptions,
    method: 'GET',
  });
  return handleResponse(response);
}

export async function logout() {
  const response = await fetch(`${API_BASE}/auth/logout`, {
    ...defaultOptions,
    method: 'POST',
    headers: {
      ...defaultOptions.headers,
      'X-CSRF-Token': getCsrfToken(),
    },
  });
  return handleResponse(response);
}

export async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...defaultOptions,
    ...options,
    headers: {
      ...defaultOptions.headers,
      ...options.headers,
      ...(options.method && options.method !== 'GET'
        ? { 'X-CSRF-Token': getCsrfToken() }
        : {}),
    },
    credentials: 'include',
  });
  return handleResponse(response);
}

export function getCsrfToken() {
  const match = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : undefined;
}
