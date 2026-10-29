import { useState, useEffect, useRef, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Bell,
  CheckCheck,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Activity,
  FileText,
  HelpCircle,
  KeyRound,
  Sliders,
  RefreshCw,
  Clock,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { notificationService } from '../../services/notification.service';
import type { Notification, NotificationCategory, NotificationSeverity } from '../../types';
import { cn } from '../../lib/utils';

interface NotificationDropdownProps {
  className?: string;
}

export function NotificationDropdown({ className }: NotificationDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<NotificationCategory | 'ALL' | 'UNREAD'>('ALL');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dropdownRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  // ─── Fetch Unread Count ─────────────────────────────────────────────────────
  const fetchUnreadCount = useCallback(async () => {
    try {
      const count = await notificationService.getUnreadCount();
      setUnreadCount(count);
    } catch {
      // silently retain existing count
    }
  }, []);

  // ─── Fetch Notifications List ───────────────────────────────────────────────
  const fetchNotifications = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const query: any = { limit: 15, page: 1 };
      if (selectedCategory === 'UNREAD') {
        query.isRead = false;
      } else if (selectedCategory !== 'ALL') {
        query.category = selectedCategory;
      }

      const res = await notificationService.getNotifications(query);
      setNotifications(res.notifications);
      setUnreadCount(res.unreadCount);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load notifications');
    } finally {
      setIsLoading(false);
    }
  }, [selectedCategory]);

  // ─── Initial Load & Real-Time Listeners ─────────────────────────────────────
  useEffect(() => {
    fetchUnreadCount();

    // Socket.IO real-time listener for incoming events
    const unsubNotification = notificationService.onNewNotification((newNotif) => {
      setUnreadCount((prev) => prev + 1);
      setNotifications((prev) => [newNotif, ...prev.filter((n) => n._id !== newNotif._id)]);
    });

    const unsubCount = notificationService.onUnreadCountChange((newCount) => {
      setUnreadCount(newCount);
    });

    // Window focus & visibility re-validation
    const handleFocus = () => {
      fetchUnreadCount();
    };
    window.addEventListener('focus', handleFocus);

    return () => {
      unsubNotification();
      unsubCount();
      window.removeEventListener('focus', handleFocus);
    };
  }, [fetchUnreadCount]);

  // Refetch list when dropdown opens or category tab changes
  useEffect(() => {
    if (isOpen) {
      fetchNotifications();
    }
  }, [isOpen, selectedCategory, fetchNotifications]);

  // Close dropdown on click outside or Escape key
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  // ─── Mark As Read ───────────────────────────────────────────────────────────
  const handleItemClick = async (notification: Notification) => {
    if (!notification.isRead) {
      try {
        await notificationService.markAsRead(notification._id);
        setNotifications((prev) =>
          prev.map((n) => (n._id === notification._id ? { ...n, isRead: true } : n))
        );
        setUnreadCount((prev) => Math.max(0, prev - 1));
      } catch {
        // Continue navigation regardless
      }
    }

    setIsOpen(false);
    if (notification.actionUrl) {
      navigate(notification.actionUrl);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      const categoryArg = selectedCategory === 'ALL' || selectedCategory === 'UNREAD' ? undefined : selectedCategory;
      await notificationService.markAllAsRead(categoryArg);
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
      setUnreadCount(0);
    } catch {
      // ignore
    }
  };

  const formatRelativeTime = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffMins < 1) return 'Just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      if (diffDays === 1) return 'Yesterday';
      return `${diffDays}d ago`;
    } catch {
      return '';
    }
  };

  const getSeverityBadge = (severity: NotificationSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          badge: 'bg-rose-50 text-rose-700 border-rose-200',
          icon: ShieldAlert,
          iconColor: 'text-rose-600',
          dot: 'bg-rose-500',
          label: 'Critical',
        };
      case 'HIGH':
        return {
          badge: 'bg-amber-50 text-amber-800 border-amber-200',
          icon: AlertTriangle,
          iconColor: 'text-amber-600',
          dot: 'bg-amber-500',
          label: 'High',
        };
      case 'MEDIUM':
        return {
          badge: 'bg-orange-50 text-orange-700 border-orange-200',
          icon: Activity,
          iconColor: 'text-orange-600',
          dot: 'bg-orange-500',
          label: 'Medium',
        };
      case 'LOW':
        return {
          badge: 'bg-blue-50 text-blue-700 border-blue-200',
          icon: Info,
          iconColor: 'text-blue-600',
          dot: 'bg-blue-500',
          label: 'Low',
        };
      default:
        return {
          badge: 'bg-slate-50 text-slate-700 border-slate-200',
          icon: ShieldCheck,
          iconColor: 'text-slate-600',
          dot: 'bg-slate-400',
          label: 'Info',
        };
    }
  };

  const getCategoryIcon = (category: NotificationCategory) => {
    switch (category) {
      case 'SECURITY':
        return ShieldAlert;
      case 'SCAN':
        return Activity;
      case 'THREAT_INTELLIGENCE':
        return AlertTriangle;
      case 'REPORT':
        return FileText;
      case 'SUPPORT':
        return HelpCircle;
      case 'ACCOUNT_SECURITY':
        return KeyRound;
      default:
        return Bell;
    }
  };

  return (
    <div className={cn('relative', className)} ref={dropdownRef}>
      {/* ── Bell Trigger Button ── */}
      <button
        id="navbar-notification-bell-btn"
        type="button"
        aria-label={`Notifications ${unreadCount > 0 ? `(${unreadCount} unread)` : ''}`}
        aria-expanded={isOpen}
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'relative p-2 rounded-xl transition-all duration-150 border',
          isOpen
            ? 'bg-blue-50 border-blue-200 text-blue-700 ring-2 ring-blue-600/10'
            : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/80 border-slate-200/80 bg-white shadow-xs'
        )}
      >
        <Bell className="w-4 h-4" />
        {unreadCount > 0 && (
          <span
            className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 bg-blue-600 text-white text-[10px] font-bold rounded-full flex items-center justify-center border-2 border-white shadow-sm animate-in zoom-in duration-150"
            aria-live="polite"
          >
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* ── Notification Dropdown Menu ── */}
      {isOpen && (
        <div
          role="region"
          aria-label="Notifications panel"
          className="absolute right-0 top-full mt-2 w-[340px] sm:w-[410px] bg-white border border-slate-200 rounded-2xl shadow-2xl z-50 overflow-hidden flex flex-col max-h-[82vh] animate-in fade-in zoom-in-95 duration-150"
        >
          {/* Header */}
          <div className="p-3.5 border-b border-slate-100 bg-slate-50/60 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold text-slate-900 tracking-tight">Security Notifications</h3>
              {unreadCount > 0 && (
                <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md bg-blue-100 text-blue-700 border border-blue-200">
                  {unreadCount} unread
                </span>
              )}
            </div>

            <div className="flex items-center gap-1.5">
              {unreadCount > 0 && (
                <button
                  type="button"
                  onClick={handleMarkAllRead}
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-600 hover:text-blue-600 px-2 py-1 rounded-md hover:bg-white transition-colors"
                  title="Mark all notifications as read"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  <span>Mark all read</span>
                </button>
              )}
              <Link
                to="/notifications"
                onClick={() => setIsOpen(false)}
                className="p-1 text-slate-500 hover:text-slate-800 rounded-md hover:bg-white transition-colors"
                title="Notification Settings & Center"
              >
                <Sliders className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Filter Tabs */}
          <div className="px-3 pt-2.5 pb-2 border-b border-slate-100 flex items-center gap-1 overflow-x-auto no-scrollbar">
            {(
              [
                { id: 'ALL', label: 'All' },
                { id: 'UNREAD', label: 'Unread' },
                { id: 'SECURITY', label: 'Security' },
                { id: 'SCAN', label: 'Scans' },
                { id: 'THREAT_INTELLIGENCE', label: 'Threat Intel' },
                { id: 'REPORT', label: 'Reports' },
                { id: 'SUPPORT', label: 'Support' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSelectedCategory(tab.id as any)}
                className={cn(
                  'text-[11px] font-semibold px-2.5 py-1 rounded-lg transition-all shrink-0 whitespace-nowrap',
                  selectedCategory === tab.id
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Notifications List Body */}
          <div className="overflow-y-auto flex-1 divide-y divide-slate-100">
            {isLoading ? (
              <div className="py-12 flex flex-col items-center justify-center text-slate-400 gap-2">
                <RefreshCw className="w-5 h-5 animate-spin text-blue-600" />
                <p className="text-xs font-medium">Loading notifications...</p>
              </div>
            ) : error ? (
              <div className="p-6 text-center space-y-2">
                <AlertTriangle className="w-6 h-6 text-amber-500 mx-auto" />
                <p className="text-xs font-semibold text-slate-800">Notifications couldn't be loaded</p>
                <p className="text-[11px] text-slate-500">{error}</p>
                <button
                  type="button"
                  onClick={fetchNotifications}
                  className="mt-2 text-xs font-semibold text-blue-600 hover:text-blue-700 underline"
                >
                  Try Again
                </button>
              </div>
            ) : notifications.length === 0 ? (
              <div className="py-10 px-4 text-center space-y-2">
                <div className="w-10 h-10 rounded-full bg-slate-50 text-slate-400 border border-slate-200 flex items-center justify-center mx-auto">
                  <ShieldCheck className="w-5 h-5 text-emerald-600" />
                </div>
                <p className="text-xs font-bold text-slate-800">You're all caught up</p>
                <p className="text-[11px] text-slate-500 max-w-[240px] mx-auto leading-relaxed">
                  No notifications found for this category. New security findings and alerts will appear here in real time.
                </p>
              </div>
            ) : (
              notifications.map((item) => {
                const sevConfig = getSeverityBadge(item.severity);
                const SevIcon = sevConfig.icon;
                const CatIcon = getCategoryIcon(item.category);

                return (
                  <div
                    key={item._id}
                    onClick={() => handleItemClick(item)}
                    className={cn(
                      'p-3.5 flex items-start gap-3 transition-colors cursor-pointer group text-left relative',
                      item.isRead ? 'bg-white hover:bg-slate-50/80' : 'bg-blue-50/35 hover:bg-blue-50/60'
                    )}
                  >
                    {/* Unread indicator bar */}
                    {!item.isRead && (
                      <span className="absolute left-0 top-3 bottom-3 w-1 bg-blue-600 rounded-r-sm" />
                    )}

                    {/* Icon container */}
                    <div
                      className={cn(
                        'w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border mt-0.5',
                        sevConfig.badge
                      )}
                    >
                      <SevIcon className={cn('w-4 h-4', sevConfig.iconColor)} />
                    </div>

                    {/* Content */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center justify-between gap-1 mb-0.5">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span
                            className={cn(
                              'text-[9px] font-bold uppercase px-1.5 py-0.2 rounded border shrink-0',
                              sevConfig.badge
                            )}
                          >
                            {sevConfig.label}
                          </span>
                          <span className="text-[10px] font-semibold text-slate-500 truncate flex items-center gap-1">
                            <CatIcon className="w-3 h-3" />
                            {item.category.replace('_', ' ')}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-400 shrink-0 flex items-center gap-0.5">
                          <Clock className="w-2.5 h-2.5" />
                          {formatRelativeTime(item.createdAt)}
                        </span>
                      </div>

                      <h4
                        className={cn(
                          'text-xs font-bold leading-snug line-clamp-1 group-hover:text-blue-600 transition-colors',
                          item.isRead ? 'text-slate-800' : 'text-slate-900'
                        )}
                      >
                        {item.title}
                      </h4>

                      <p className="text-[11px] text-slate-600 line-clamp-2 mt-0.5 leading-relaxed">
                        {item.message}
                      </p>

                      {item.actionUrl && (
                        <div className="mt-1.5 flex items-center gap-1 text-[11px] font-semibold text-blue-600 group-hover:underline">
                          <span>{item.actionText || 'View Details'}</span>
                          <ExternalLink className="w-3 h-3" />
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="p-2.5 bg-slate-50 border-t border-slate-100 flex items-center justify-between text-xs">
            <Link
              to="/notifications"
              onClick={() => setIsOpen(false)}
              className="text-[11px] font-bold text-blue-600 hover:text-blue-700 px-2 py-1 rounded hover:bg-white transition-colors"
            >
              View Notification Center →
            </Link>
            <Link
              to="/settings"
              onClick={() => setIsOpen(false)}
              className="text-[11px] font-medium text-slate-500 hover:text-slate-800 px-2 py-1 rounded hover:bg-white transition-colors"
            >
              Preferences
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
