import axios from 'axios';

// ─── API Client ───────────────────────────────────────────────────────────────
// Centralized Axios instance — all API calls go through here.
// VITE_API_URL comes from .env — never hardcode production URLs.

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 45000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ─── Request Interceptor ──────────────────────────────────────────────────────
// Attach JWT token from storage to every request.
// Token storage is isolated here — not scattered across components.
apiClient.interceptors.request.use(
  (config) => {
    const token = getStoredToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ─── Response Interceptor ─────────────────────────────────────────────────────
// Handle 401 globally — clear stale tokens.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid — clear stored auth state
      removeStoredToken();
    }
    return Promise.reject(error);
  }
);

// ─── Token Storage ────────────────────────────────────────────────────────────
// Token storage is deliberately isolated to this file.
//
// ARCHITECTURE NOTE:
// Currently using localStorage for development ergonomics.
// This is a known trade-off — localStorage is accessible to JavaScript (XSS risk).
// Production upgrade path: migrate to HttpOnly SameSite=Strict Secure cookies.
// The cookie approach requires backend changes to set/clear cookies.
// By isolating token access here, migration only requires updating these 3 functions.
//
// NEVER store: passwords, passwordHash, or sensitive PII in storage.

const TOKEN_KEY = 'cw_auth_token';

export function storeToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function removeStoredToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}
