// Storage service for CyberWatch Extension
// Architecture: Stores sensitive JWT in chrome.storage.session (cleared when browser closes).
// Stores non-sensitive preferences (e.g. API URL, last selected scanner) in chrome.storage.local.

const DEFAULT_API_BASE = 'http://localhost:5000/api/v1';
const DEFAULT_WEB_BASE = 'http://localhost:5173';

const TOKEN_KEY = 'cw_ext_session_token';
const USER_KEY = 'cw_ext_session_user';
const CONFIG_KEY = 'cw_ext_config';

export interface ExtConfig {
  apiBaseUrl: string;
  webBaseUrl: string;
}

// In-memory fallback for testing, pre-render, or environments where chrome.storage is unavailable
const memoryStore: Record<string, any> = {};

const fallbackStorage: chrome.storage.StorageArea = {
  async get(keys?: any) {
    if (!keys) return { ...memoryStore };
    if (typeof keys === 'string') return { [keys]: memoryStore[keys] };
    if (Array.isArray(keys)) {
      const res: Record<string, any> = {};
      keys.forEach((k) => {
        if (k in memoryStore) res[k] = memoryStore[k];
      });
      return res;
    }
    return { ...memoryStore };
  },
  async set(items: Record<string, any>) {
    Object.assign(memoryStore, items);
  },
  async remove(keys: string | string[]) {
    const list = Array.isArray(keys) ? keys : [keys];
    list.forEach((k) => delete memoryStore[k]);
  },
  async clear() {
    Object.keys(memoryStore).forEach((k) => delete memoryStore[k]);
  },
} as chrome.storage.StorageArea;

// Check if chrome.storage.session or local is supported
function getSessionStorage(): chrome.storage.StorageArea {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    if (chrome.storage.session) {
      return chrome.storage.session;
    }
    if (chrome.storage.local) {
      return chrome.storage.local;
    }
  }
  return fallbackStorage;
}

export const storageService = {
  /**
   * Save JWT token to ephemeral session storage.
   * Never written to persistent cookies or unencrypted local files.
   */
  async setToken(token: string): Promise<void> {
    const storage = getSessionStorage();
    await storage.set({ [TOKEN_KEY]: token });
  },

  /**
   * Retrieve JWT token from session storage.
   */
  async getToken(): Promise<string | null> {
    const storage = getSessionStorage();
    const result = await storage.get(TOKEN_KEY);
    return (result && result[TOKEN_KEY]) || null;
  },

  /**
   * Clear session token (logout).
   */
  async clearToken(): Promise<void> {
    const storage = getSessionStorage();
    await storage.remove([TOKEN_KEY, USER_KEY]);
  },

  /**
   * Save user profile info (name, email, role) to session storage.
   */
  async setUser(user: any): Promise<void> {
    const storage = getSessionStorage();
    await storage.set({ [USER_KEY]: user });
  },

  /**
   * Get user profile info from session storage.
   */
  async getUser(): Promise<any | null> {
    const storage = getSessionStorage();
    const result = await storage.get(USER_KEY);
    return (result && result[USER_KEY]) || null;
  },

  /**
   * Save configurable backend & frontend base URLs to local storage.
   */
  async setConfig(config: Partial<ExtConfig>): Promise<void> {
    const current = await this.getConfig();
    const apiBaseUrl = (config.apiBaseUrl ?? current.apiBaseUrl).trim().replace(/\/+$/, '');
    const webBaseUrl = (config.webBaseUrl ?? current.webBaseUrl).trim().replace(/\/+$/, '');
    const updated = { apiBaseUrl, webBaseUrl };
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ [CONFIG_KEY]: updated });
    } else {
      await fallbackStorage.set({ [CONFIG_KEY]: updated });
    }
  },

  /**
   * Retrieve configured URLs. Defaults to verified local dev configuration.
   */
  async getConfig(): Promise<ExtConfig> {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const result = await chrome.storage.local.get(CONFIG_KEY);
        const stored = (result && result[CONFIG_KEY]) || {};
        return {
          apiBaseUrl: (stored.apiBaseUrl || DEFAULT_API_BASE).trim().replace(/\/+$/, ''),
          webBaseUrl: (stored.webBaseUrl || DEFAULT_WEB_BASE).trim().replace(/\/+$/, ''),
        };
      }
    } catch {
      // Fallback if storage access throws
    }
    const memResult = await fallbackStorage.get(CONFIG_KEY);
    const stored = (memResult && memResult[CONFIG_KEY]) || {};
    return {
      apiBaseUrl: (stored.apiBaseUrl || DEFAULT_API_BASE).trim().replace(/\/+$/, ''),
      webBaseUrl: (stored.webBaseUrl || DEFAULT_WEB_BASE).trim().replace(/\/+$/, ''),
    };
  },
};
