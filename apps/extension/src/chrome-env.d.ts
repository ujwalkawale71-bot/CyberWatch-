// Ambient declarations for Chrome Extension APIs

declare namespace chrome {
  export namespace tabs {
    export interface Tab {
      id?: number;
      url?: string;
      title?: string;
      active?: boolean;
    }
    export function query(queryInfo: { active?: boolean; currentWindow?: boolean }): Promise<Tab[]>;
    export function query(queryInfo: { active?: boolean; currentWindow?: boolean }, callback: (tabs: Tab[]) => void): void;
    export function create(createProperties: { url?: string; active?: boolean }): Promise<Tab>;
    export function create(createProperties: { url?: string; active?: boolean }, callback?: (tab: Tab) => void): void;
  }

  export namespace storage {
    export interface StorageArea {
      get(keys?: string | string[] | Record<string, any> | null): Promise<Record<string, any>>;
      get(keys: string | string[] | Record<string, any> | null, callback: (items: Record<string, any>) => void): void;
      set(items: Record<string, any>): Promise<void>;
      set(items: Record<string, any>, callback?: () => void): void;
      remove(keys: string | string[]): Promise<void>;
      remove(keys: string | string[], callback?: () => void): void;
      clear(): Promise<void>;
      clear(callback?: () => void): void;
    }
    export const local: StorageArea;
    export const session: StorageArea | undefined;
    export const sync: StorageArea;
  }

  export namespace runtime {
    export interface MessageSender {
      id?: string;
      url?: string;
      tab?: tabs.Tab;
    }
    export const lastError: { message?: string } | undefined;
    export function sendMessage(message: any): Promise<any>;
    export function sendMessage(message: any, responseCallback?: (response: any) => void): void;
    export const onMessage: {
      addListener(callback: (message: any, sender: MessageSender, sendResponse: (response?: any) => void) => boolean | void): void;
      removeListener(callback: Function): void;
    };
    export function getURL(path: string): string;
  }
}
