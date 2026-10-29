import { apiClient, storeToken, removeStoredToken } from '../lib/api';
import type { User, AuthResponse, ApiResponse } from '../types';

// ─── Auth Service ─────────────────────────────────────────────────────────────
// All authentication API calls go through here.
// Components and context never make raw fetch/axios calls directly.

export type RegisterData = {
  name: string;
  email: string;
  password: string;
};

export type LoginData = {
  email: string;
  password: string;
};

export const authService = {
  // ── Register ────────────────────────────────────────────────────────────────
  async register(data: RegisterData): Promise<AuthResponse['data']> {
    const response = await apiClient.post<AuthResponse>('/auth/register', data);
    const { token, user } = response.data.data;
    storeToken(token);
    return { token, user };
  },

  // ── Login ────────────────────────────────────────────────────────────────────
  async login(data: LoginData): Promise<AuthResponse['data']> {
    const response = await apiClient.post<AuthResponse>('/auth/login', data);
    const { token, user } = response.data.data;
    storeToken(token);
    return { token, user };
  },

  // ── Get Current User ─────────────────────────────────────────────────────────
  async getCurrentUser(): Promise<User> {
    const response = await apiClient.get<ApiResponse<{ user: User }>>('/auth/me');
    return response.data.data!.user;
  },

  // ── Logout ───────────────────────────────────────────────────────────────────
  // Calls backend logout endpoint, then removes stored token.
  // JWT is stateless — the client removing the token is what matters.
  async logout(): Promise<void> {
    try {
      await apiClient.post('/auth/logout');
    } catch {
      // Always remove token even if the API call fails
    } finally {
      removeStoredToken();
    }
  },
};
