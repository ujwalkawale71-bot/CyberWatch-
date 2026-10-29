import { io, Socket } from 'socket.io-client';
import { apiClient } from '../lib/api';
import type {
  ApiResponse,
  Notification,
  NotificationCategory,
  NotificationPreferences,
  GetNotificationsQuery,
  GetNotificationsResponse,
} from '../types';

class NotificationService {
  private socket: Socket | null = null;
  private notificationListeners: Set<(notification: Notification) => void> = new Set();
  private unreadCountListeners: Set<(count: number) => void> = new Set();
  private isInitialized = false;

  private getSocketUrl(): string {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1';
    return apiUrl.replace(/\/api\/v1\/?$/, '');
  }

  public initSocket(): void {
    if (this.socket?.connected || this.isInitialized) return;

    const token = localStorage.getItem('token') || localStorage.getItem('auth_token');
    if (!token) return;

    const socketUrl = this.getSocketUrl();
    this.socket = io(socketUrl, {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 10,
      reconnectionDelay: 2500,
    });

    this.socket.on('notification:new', (notification: Notification) => {
      this.notificationListeners.forEach((listener) => listener(notification));
    });

    this.socket.on('notification:unread_count', ({ unreadCount }: { unreadCount: number }) => {
      this.unreadCountListeners.forEach((listener) => listener(unreadCount));
    });

    this.isInitialized = true;
  }

  public onNewNotification(callback: (notification: Notification) => void): () => void {
    this.notificationListeners.add(callback);
    this.initSocket();
    return () => {
      this.notificationListeners.delete(callback);
    };
  }

  public onUnreadCountChange(callback: (count: number) => void): () => void {
    this.unreadCountListeners.add(callback);
    this.initSocket();
    return () => {
      this.unreadCountListeners.delete(callback);
    };
  }

  public disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isInitialized = false;
    }
  }

  // ─── REST API Methods ───────────────────────────────────────────────────────

  async getNotifications(query: GetNotificationsQuery = {}): Promise<GetNotificationsResponse> {
    const response = await apiClient.get<ApiResponse<GetNotificationsResponse>>('/notifications', {
      params: query,
    });

    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Failed to load notifications');
    }

    return response.data.data;
  }

  async getUnreadCount(): Promise<number> {
    try {
      const response = await apiClient.get<ApiResponse<{ unreadCount: number }>>(
        '/notifications/unread-count'
      );
      return response.data.data?.unreadCount ?? 0;
    } catch {
      return 0;
    }
  }

  async markAsRead(notificationId: string): Promise<Notification> {
    const response = await apiClient.patch<ApiResponse<Notification>>(
      `/notifications/${notificationId}/read`
    );
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Failed to mark notification as read');
    }
    return response.data.data;
  }

  async markAllAsRead(category?: NotificationCategory): Promise<number> {
    const response = await apiClient.patch<ApiResponse<{ modifiedCount: number }>>(
      '/notifications/read-all',
      category ? { category } : {}
    );
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Failed to mark all as read');
    }
    return response.data.data.modifiedCount;
  }

  async deleteNotification(notificationId: string): Promise<void> {
    const response = await apiClient.delete<ApiResponse<void>>(
      `/notifications/${notificationId}`
    );
    if (!response.data.success) {
      throw new Error(response.data.message || 'Failed to delete notification');
    }
  }

  async getPreferences(): Promise<NotificationPreferences> {
    const response = await apiClient.get<ApiResponse<NotificationPreferences>>(
      '/notifications/preferences'
    );
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Failed to load preferences');
    }
    return response.data.data;
  }

  async updatePreferences(
    preferences: Partial<NotificationPreferences>
  ): Promise<NotificationPreferences> {
    const response = await apiClient.patch<ApiResponse<NotificationPreferences>>(
      '/notifications/preferences',
      preferences
    );
    if (!response.data.success || !response.data.data) {
      throw new Error(response.data.message || 'Failed to update preferences');
    }
    return response.data.data;
  }
}

export const notificationService = new NotificationService();
