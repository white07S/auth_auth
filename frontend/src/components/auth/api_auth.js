const DEFAULT_HEADERS = {
  Accept: "application/json",
};

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

const readCookie = (name) => {
  const value = document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  if (!value) {
    return null;
  }
  return decodeURIComponent(value.split("=", 2)[1]);
};

const withCsrf = (options = {}, csrfCookie = "bff_csrf", csrfHeader = "x-csrf-token") => {
  const method = (options.method || "GET").toUpperCase();
  if (["GET", "HEAD", "OPTIONS"].includes(method)) {
    return options;
  }
  const token = readCookie(csrfCookie);
  const headers = { ...(options.headers || {}) };
  if (token) {
    headers[csrfHeader] = token;
  }
  return { ...options, headers };
};

const request = async (path, options = {}, csrfConfig = {}) => {
  const config = {
    credentials: "include",
    ...options,
    headers: { ...DEFAULT_HEADERS, ...(options.headers || {}) },
  };
  if (config.body && typeof config.body === "object" && !(config.body instanceof FormData)) {
    if (!config.headers["Content-Type"]) {
      config.headers["Content-Type"] = "application/json";
    }
    config.body = JSON.stringify(config.body);
  }
  const { cookieName = "bff_csrf", headerName = "x-csrf-token" } = csrfConfig;
  const finalConfig = withCsrf(config, cookieName, headerName);

  const response = await fetch(path, finalConfig);
  const text = await response.text();
  const body = text ? safeJsonParse(text) : null;

  if (!response.ok) {
    throw new ApiError(body?.detail || "Request failed", response.status, body);
  }

  return body;
};

const safeJsonParse = (text) => {
  try {
    return JSON.parse(text);
  } catch (error) {
    return null;
  }
};

export { request, ApiError, readCookie };
