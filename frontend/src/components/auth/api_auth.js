const BASE_URL = process.env.REACT_APP_BFF_BASE_URL || '';
const CSRF_COOKIE = 'XSRF-TOKEN';
const CSRF_HEADER = 'X-CSRF-Token';

const defaultHeaders = {
  Accept: 'application/json',
  'Content-Type': 'application/json',
};

const getCookie = (name) => {
  if (typeof document === 'undefined') {
    return null;
  }
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop().split(';').shift();
  }
  return null;
};

const buildUrl = (path) => `${BASE_URL}${path}`;

export const login = (redirectTarget) => {
  const search = redirectTarget ? `?redirect=${encodeURIComponent(redirectTarget)}` : '';
  window.location.assign(buildUrl(`/auth/login${search}`));
};

export const getMe = async () => request('/auth/me', { method: 'GET' });

export const logout = async () => request('/auth/logout', { method: 'POST' });

export const refresh = async () => request('/auth/refresh', { method: 'POST' });

export const heartbeat = async () => request('/auth/heartbeat', { method: 'POST' });

const request = async (path, options = {}) => {
  const { method = 'GET', body, headers = {} } = options;
  const isMutating = method !== 'GET';
  const csrfToken = isMutating ? getCookie(CSRF_COOKIE) : null;

  const finalHeaders = { ...defaultHeaders, ...headers };

  if (isMutating) {
    if (!csrfToken) {
      throw new Error('Missing CSRF token.');
    }
    finalHeaders[CSRF_HEADER] = csrfToken;
  }

  const response = await fetch(buildUrl(path), {
    method,
    body: body ? JSON.stringify(body) : undefined,
    headers: finalHeaders,
    credentials: 'include',
  });

  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data?.detail || 'Request failed');
    error.status = response.status;
    error.payload = data;
    throw error;
  }

  return data;
};

