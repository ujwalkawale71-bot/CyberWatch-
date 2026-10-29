import { useState, useEffect, useCallback } from 'react';
import type { MouseEvent } from 'react';
import { Link } from 'react-router-dom';
import {
  Bell,
  ShieldAlert,
  ShieldCheck,
  Activity,
  FileText,
  HelpCircle,
  KeyRound,
  Trash2,
  CheckCircle2,
  CheckCheck,
  Search,
  RefreshCw,
  ExternalLink,
  Clock,
  Sliders,
  AlertTriangle,
  Info,
  ChevronLeft,
  ChevronRight,
  X,
} from 'lucide-react';
import { notificationService } from '../services/notification.service';
import type {
  Notification,
  NotificationCategory,
  NotificationSeverity,
  NotificationPreferences,
} from '../types';
import { cn } from '../lib/utils';

export function NotificationCenterPage() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<NotificationCategory | 'ALL'>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<NotificationSeverity | 'ALL'>('ALL');
  const [readFilter, setReadFilter] = useState<'all' | 'true' | 'false'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Preferences Modal
  const [preferencesOpen, setPreferencesOpen] = useState(false);
  const [preferences, setPreferences] = useState<NotificationPreferences | null>(null);
  const [prefLoading, setPrefLoading] = useState(false);
  const [prefSaving, setPrefSaving] = useState(false);
  const [prefSuccess, setPrefSuccess] = useState(false);

  // ─── Fetch Notifications ───────────────────────────────────────────────────
  const fetchNotifications = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await notificationService.getNotifications({
        page,
        limit: 15,
        category: selectedCategory === 'ALL' ? undefined : selectedCategory,
        severity: selectedSeverity === 'ALL' ? undefined : selectedSeverity,
        isRead: readFilter,
        search: searchQuery.trim() || undefined,
      });

      setNotifications(res.notifications);
      setTotal(res.total);
      setTotalPages(res.totalPages);
      setUnreadCount(res.unreadCount);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load notifications');
    } finally {
      setIsLoading(false);
    }
  }, [page, selectedCategory, selectedSeverity, readFilter, searchQuery]);

  useEffect(() => {
    fetchNotifications();
  }, [fetchNotifications]);

  // Real-time notification updates
  useEffect(() => {
    const unsubNotification = notificationService.onNewNotification(() => {
      fetchNotifications();
    });
    const unsubCount = notificationService.onUnreadCountChange((newCount) => {
      setUnreadCount(newCount);
    });

    return () => {
      unsubNotification();
      unsubCount();
    };
  }, [fetchNotifications]);

  // ─── Actions ───────────────────────────────────────────────────────────────
  const handleMarkRead = async (id: string) => {
    try {
      await notificationService.markAsRead(id);
      setNotifications((prev) =>
        prev.map((n) => (n._id === id ? { ...n, isRead: true } : n))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch (err) {
      console.error(err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      const cat = selectedCategory === 'ALL' ? undefined : selectedCategory;
      await notificationService.markAllAsRead(cat);
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
      setUnreadCount(0);
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async (id: string, e: MouseEvent) => {
    e.stopPropagation();
    try {
      await notificationService.deleteNotification(id);
      setNotifications((prev) => prev.filter((n) => n._id !== id));
      setTotal((prev) => Math.max(0, prev - 1));
    } catch (err) {
      console.error(err);
    }
  };

  // ─── Preferences Handlers ──────────────────────────────────────────────────
  const openPreferences = async () => {
    setPreferencesOpen(true);
    setPrefLoading(true);
    setPrefSuccess(false);
    try {
      const data = await notificationService.getPreferences();
      setPreferences(data);
    } catch (err) {
      console.error(err);
    } finally {
      setPrefLoading(false);
    }
  };

  const handleTogglePref = (key: keyof NotificationPreferences) => {
    if (key === 'securityAlerts' || key === 'accountSecurity') return; // Mandatory
    if (!preferences) return;
    setPreferences({ ...preferences, [key]: !preferences[key] });
  };

  const handleSavePreferences = async () => {
    if (!preferences) return;
    setPrefSaving(true);
    try {
      const updated = await notificationService.updatePreferences(preferences);
      setPreferences(updated);
      setPrefSuccess(true);
      setTimeout(() => setPrefSuccess(false), 2500);
    } catch (err) {
      console.error(err);
    } finally {
      setPrefSaving(false);
    }
  };

  const getSeverityBadge = (severity: NotificationSeverity) => {
    switch (severity) {
      case 'CRITICAL':
        return {
          badge: 'bg-rose-50 text-rose-700 border-rose-200',
          icon: ShieldAlert,
          iconColor: 'text-rose-600',
          label: 'Critical',
        };
      case 'HIGH':
        return {
          badge: 'bg-amber-50 text-amber-800 border-amber-200',
          icon: AlertTriangle,
          iconColor: 'text-amber-600',
          label: 'High',
        };
      case 'MEDIUM':
        return {
          badge: 'bg-orange-50 text-orange-700 border-orange-200',
          icon: Activity,
          iconColor: 'text-orange-600',
          label: 'Medium',
        };
      case 'LOW':
        return {
          badge: 'bg-blue-50 text-blue-700 border-blue-200',
          icon: Info,
          iconColor: 'text-blue-600',
          label: 'Low',
        };
      default:
        return {
          badge: 'bg-slate-50 text-slate-700 border-slate-200',
          icon: ShieldCheck,
          iconColor: 'text-slate-600',
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

  const criticalCount = notifications.filter(
    (n) => n.severity === 'CRITICAL' || n.severity === 'HIGH'
  ).length;

  return (
    <div className="min-h-screen bg-slate-50/50 pb-16">
      {/* ── Page Header ── */}
      <div className="bg-white border-b border-slate-200 pt-[72px]">
        <div className="max-w-[1560px] mx-auto px-4 sm:px-6 lg:px-8 2xl:px-10 py-6 sm:py-8">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold text-blue-600 mb-1.5">
                <Link to="/dashboard" className="hover:underline">Dashboard</Link>
                <span>/</span>
                <span className="text-slate-500">Notifications</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5 sm:gap-3">
                <Bell className="w-5 h-5 sm:w-6 sm:h-6 text-blue-600 shrink-0" />
                <span>Security Notification Center</span>
              </h1>
              <p className="text-xs sm:text-sm text-slate-500 mt-1 max-w-3xl leading-relaxed">
                Live security events, scanner results, Threat Intelligence matches, and system alerts.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
              <button
                type="button"
                onClick={openPreferences}
                className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-xl hover:bg-slate-50 shadow-xs transition-colors"
              >
                <Sliders className="w-4 h-4 text-slate-500" />
                Preferences
              </button>

              {unreadCount > 0 && (
                <button
                  type="button"
                  onClick={handleMarkAllRead}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 rounded-xl shadow-xs transition-colors"
                >
                  <CheckCheck className="w-4 h-4" />
                  Mark All Read
                </button>
              )}
            </div>
          </div>

          {/* Metric Stats Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
            <div className="p-4 bg-slate-50 rounded-xl border border-slate-200/80">
              <p className="text-xs font-medium text-slate-500">Total Alerts</p>
              <p className="text-xl font-bold text-slate-900 mt-1">{total}</p>
            </div>
            <div className="p-4 bg-blue-50/50 rounded-xl border border-blue-100">
              <p className="text-xs font-medium text-blue-700">Unread Items</p>
              <p className="text-xl font-bold text-blue-800 mt-1">{unreadCount}</p>
            </div>
            <div className="p-4 bg-rose-50/50 rounded-xl border border-rose-100">
              <p className="text-xs font-medium text-rose-700">Critical / High Threat</p>
              <p className="text-xl font-bold text-rose-800 mt-1">{criticalCount}</p>
            </div>
            <div className="p-4 bg-emerald-50/50 rounded-xl border border-emerald-100">
              <p className="text-xs font-medium text-emerald-700">Real-time Stream</p>
              <p className="text-xs font-bold text-emerald-800 mt-2 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Active &amp; Connected
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Main Content Container ── */}
      <div className="max-w-[1560px] mx-auto px-4 sm:px-6 lg:px-8 2xl:px-10 py-8">
        {/* Filter Controls Bar */}
        <div className="bg-white p-4 rounded-2xl border border-slate-200 shadow-xs mb-6 space-y-4">
          {/* Category Tabs */}
          <div className="flex items-center gap-2 overflow-x-auto no-scrollbar pb-1">
            {(
              [
                { id: 'ALL', label: 'All Categories' },
                { id: 'SECURITY', label: 'Security Alerts' },
                { id: 'SCAN', label: 'Scans' },
                { id: 'THREAT_INTELLIGENCE', label: 'Threat Intel' },
                { id: 'REPORT', label: 'Reports' },
                { id: 'SUPPORT', label: 'Help & Support' },
                { id: 'ACCOUNT_SECURITY', label: 'Account Security' },
                { id: 'SYSTEM', label: 'System Notices' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setSelectedCategory(tab.id as any);
                  setPage(1);
                }}
                className={cn(
                  'text-xs font-semibold px-3.5 py-1.5 rounded-xl transition-all whitespace-nowrap shrink-0',
                  selectedCategory === tab.id
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200/60'
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Sub-Filters: Search, Severity, Read State */}
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 pt-2 border-t border-slate-100">
            {/* Search */}
            <div className="sm:col-span-5 relative">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search notifications by title, target, or keywords..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                className="w-full pl-9 pr-4 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white"
              />
            </div>

            {/* Severity Filter */}
            <div className="sm:col-span-3">
              <select
                value={selectedSeverity}
                onChange={(e) => {
                  setSelectedSeverity(e.target.value as any);
                  setPage(1);
                }}
                className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white font-medium text-slate-700"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">🔴 Critical Only</option>
                <option value="HIGH">🟠 High Risk Only</option>
                <option value="MEDIUM">🟡 Medium Risk</option>
                <option value="LOW">🔵 Low Risk</option>
                <option value="INFO">ℹ️ Informational</option>
              </select>
            </div>

            {/* Read / Unread Status */}
            <div className="sm:col-span-3">
              <select
                value={readFilter}
                onChange={(e) => {
                  setReadFilter(e.target.value as any);
                  setPage(1);
                }}
                className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white font-medium text-slate-700"
              >
                <option value="all">All Read States</option>
                <option value="false">Unread Only</option>
                <option value="true">Read Only</option>
              </select>
            </div>

            {/* Refresh */}
            <div className="sm:col-span-1 flex items-center justify-end">
              <button
                type="button"
                onClick={() => fetchNotifications()}
                className="p-2 text-slate-500 hover:text-blue-600 hover:bg-slate-100 rounded-xl transition-colors border border-slate-200"
                title="Refresh notifications"
              >
                <RefreshCw className={cn('w-4 h-4', isLoading && 'animate-spin text-blue-600')} />
              </button>
            </div>
          </div>
        </div>

        {/* ── Notifications List ── */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-xs overflow-hidden">
          {isLoading ? (
            <div className="py-20 text-center space-y-3">
              <RefreshCw className="w-8 h-8 animate-spin text-blue-600 mx-auto" />
              <p className="text-sm font-semibold text-slate-700">Loading notifications...</p>
            </div>
          ) : error ? (
            <div className="py-16 text-center space-y-3">
              <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto" />
              <p className="text-sm font-bold text-slate-800">Unable to load notifications</p>
              <p className="text-xs text-slate-500">{error}</p>
              <button
                type="button"
                onClick={fetchNotifications}
                className="px-4 py-2 bg-blue-600 text-white text-xs font-bold rounded-xl hover:bg-blue-700"
              >
                Try Again
              </button>
            </div>
          ) : notifications.length === 0 ? (
            <div className="py-20 text-center space-y-3 px-4">
              <div className="w-12 h-12 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                <ShieldCheck className="w-6 h-6 text-emerald-600" />
              </div>
              <h3 className="text-base font-bold text-slate-900">You're all caught up!</h3>
              <p className="text-xs text-slate-500 max-w-sm mx-auto leading-relaxed">
                There are no notifications matching your current filters. As scanners complete and Threat Intelligence feeds discover signals, notifications will be displayed here in real time.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {notifications.map((item) => {
                const sevConfig = getSeverityBadge(item.severity);
                const SevIcon = sevConfig.icon;
                const CatIcon = getCategoryIcon(item.category);

                return (
                  <div
                    key={item._id}
                    className={cn(
                      'p-5 transition-colors flex flex-col sm:flex-row items-start justify-between gap-4 text-left relative group',
                      item.isRead ? 'bg-white hover:bg-slate-50/70' : 'bg-blue-50/25 hover:bg-blue-50/50'
                    )}
                  >
                    {!item.isRead && (
                      <span className="absolute left-0 top-3 bottom-3 w-1 bg-blue-600 rounded-r-sm" />
                    )}

                    <div className="flex items-start gap-4 min-w-0 flex-1">
                      <div
                        className={cn(
                          'w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border mt-0.5',
                          sevConfig.badge
                        )}
                      >
                        <SevIcon className={cn('w-5 h-5', sevConfig.iconColor)} />
                      </div>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2 mb-1">
                          <span
                            className={cn(
                              'text-[10px] font-bold uppercase px-2 py-0.5 rounded border',
                              sevConfig.badge
                            )}
                          >
                            {sevConfig.label}
                          </span>
                          <span className="text-xs font-semibold text-slate-500 flex items-center gap-1">
                            <CatIcon className="w-3.5 h-3.5 text-slate-400" />
                            {item.category.replace('_', ' ')}
                          </span>
                          <span className="text-slate-300">•</span>
                          <span className="text-xs text-slate-400 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(item.createdAt).toLocaleString()}
                          </span>
                        </div>

                        <h3 className="text-sm font-bold text-slate-900 mt-0.5">
                          {item.title}
                        </h3>

                        <p className="text-xs text-slate-600 mt-1 leading-relaxed max-w-3xl">
                          {item.message}
                        </p>

                        {/* Metadata Tag Preview */}
                        {item.metadata && Object.keys(item.metadata).length > 0 && (
                          <div className="mt-2.5 flex flex-wrap items-center gap-2">
                            {Boolean(item.metadata.target) && (
                              <span className="text-[11px] font-mono bg-slate-100 text-slate-700 px-2 py-0.5 rounded-md border border-slate-200/60">
                                Target: {String(item.metadata.target)}
                              </span>
                            )}
                            {item.metadata.riskScore !== undefined && (
                              <span className="text-[11px] font-bold bg-amber-50 text-amber-800 px-2 py-0.5 rounded-md border border-amber-200">
                                Risk Score: {String(item.metadata.riskScore)}/100
                              </span>
                            )}
                            {Boolean(item.metadata.indicator) && (
                              <span className="text-[11px] font-mono bg-purple-50 text-purple-700 px-2 py-0.5 rounded-md border border-purple-200">
                                IOC: {String(item.metadata.indicator)}
                              </span>
                            )}
                            {Boolean(item.metadata.ticketNumber) && (
                              <span className="text-[11px] font-mono bg-blue-50 text-blue-700 px-2 py-0.5 rounded-md border border-blue-200">
                                Ticket #{String(item.metadata.ticketNumber)}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex sm:flex-col items-center sm:items-end gap-2 shrink-0 self-end sm:self-center">
                      {item.actionUrl && (
                        <Link
                          to={item.actionUrl}
                          onClick={() => {
                            if (!item.isRead) handleMarkRead(item._id);
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 shadow-xs transition-colors"
                        >
                          <span>{item.actionText || 'View Details'}</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      )}

                      <div className="flex items-center gap-1">
                        {!item.isRead && (
                          <button
                            type="button"
                            onClick={() => handleMarkRead(item._id)}
                            className="p-1.5 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                            title="Mark as read"
                          >
                            <CheckCircle2 className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={(e) => handleDelete(item._id, e)}
                          className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="Delete notification"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="p-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between text-xs">
              <span className="text-slate-500 font-medium">
                Showing page <strong className="text-slate-800">{page}</strong> of{' '}
                <strong className="text-slate-800">{totalPages}</strong> ({total} total)
              </span>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  Previous
                </button>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  className="inline-flex items-center gap-1 px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  Next
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Preferences Modal / Drawer ── */}
      {preferencesOpen && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-100 bg-slate-50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900">Notification Preferences</h3>
              </div>
              <button
                type="button"
                onClick={() => setPreferencesOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-700 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
              {prefLoading ? (
                <div className="py-10 text-center text-slate-400">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-600 mb-2" />
                  <p className="text-xs">Loading preferences...</p>
                </div>
              ) : preferences ? (
                <div className="space-y-4">
                  <p className="text-xs text-slate-500 leading-relaxed">
                    Customize which event categories trigger in-app notifications. Mandatory security and authentication alerts cannot be disabled.
                  </p>

                  <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                    {/* Mandatory: Security */}
                    <div className="p-3.5 bg-slate-50/50 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                          <span>Security Threat Alerts</span>
                          <span className="text-[9px] font-bold uppercase bg-blue-100 text-blue-800 px-1.5 py-0.2 rounded">
                            Required
                          </span>
                        </p>
                        <p className="text-[11px] text-slate-500">Critical vulnerability and malicious findings.</p>
                      </div>
                      <input type="checkbox" checked={true} disabled className="w-4 h-4 text-blue-600 rounded opacity-60" />
                    </div>

                    {/* Mandatory: Account Security */}
                    <div className="p-3.5 bg-slate-50/50 flex items-center justify-between">
                      <div>
                        <p className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                          <span>Account Security</span>
                          <span className="text-[9px] font-bold uppercase bg-blue-100 text-blue-800 px-1.5 py-0.2 rounded">
                            Required
                          </span>
                        </p>
                        <p className="text-[11px] text-slate-500">New login sessions, credential changes, and auth events.</p>
                      </div>
                      <input type="checkbox" checked={true} disabled className="w-4 h-4 text-blue-600 rounded opacity-60" />
                    </div>

                    {/* Optional: Scan completion */}
                    <div className="p-3.5 flex items-center justify-between hover:bg-slate-50/50">
                      <div>
                        <p className="text-xs font-bold text-slate-900">Scan Completion</p>
                        <p className="text-[11px] text-slate-500">Notify when URL, file, API, or extension scans finish.</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={preferences.scanCompletion}
                        onChange={() => handleTogglePref('scanCompletion')}
                        className="w-4 h-4 text-blue-600 rounded cursor-pointer"
                      />
                    </div>

                    {/* Optional: Threat Intel */}
                    <div className="p-3.5 flex items-center justify-between hover:bg-slate-50/50">
                      <div>
                        <p className="text-xs font-bold text-slate-900">Threat Intelligence Alerts</p>
                        <p className="text-[11px] text-slate-500">Indicator reputation signals and feed updates.</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={preferences.threatIntelAlerts}
                        onChange={() => handleTogglePref('threatIntelAlerts')}
                        className="w-4 h-4 text-blue-600 rounded cursor-pointer"
                      />
                    </div>

                    {/* Optional: Reports */}
                    <div className="p-3.5 flex items-center justify-between hover:bg-slate-50/50">
                      <div>
                        <p className="text-xs font-bold text-slate-900">Report Ready Notices</p>
                        <p className="text-[11px] text-slate-500">Alerts when security assessment PDF exports are prepared.</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={preferences.reportReady}
                        onChange={() => handleTogglePref('reportReady')}
                        className="w-4 h-4 text-blue-600 rounded cursor-pointer"
                      />
                    </div>

                    {/* Optional: Support */}
                    <div className="p-3.5 flex items-center justify-between hover:bg-slate-50/50">
                      <div>
                        <p className="text-xs font-bold text-slate-900">Support &amp; Help Desk Updates</p>
                        <p className="text-[11px] text-slate-500">Ticket updates, replies from engineers, and live chat summaries.</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={preferences.supportUpdates}
                        onChange={() => handleTogglePref('supportUpdates')}
                        className="w-4 h-4 text-blue-600 rounded cursor-pointer"
                      />
                    </div>

                    {/* Optional: Browser Extension */}
                    <div className="p-3.5 flex items-center justify-between hover:bg-slate-50/50">
                      <div>
                        <p className="text-xs font-bold text-slate-900">Browser Extension Scanner</p>
                        <p className="text-[11px] text-slate-500">Extension manifest and permissions audit notifications.</p>
                      </div>
                      <input
                        type="checkbox"
                        checked={preferences.browserExtensionAlerts}
                        onChange={() => handleTogglePref('browserExtensionAlerts')}
                        className="w-4 h-4 text-blue-600 rounded cursor-pointer"
                      />
                    </div>
                  </div>
                </div>
              ) : null}
            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
              {prefSuccess ? (
                <span className="text-xs font-bold text-emerald-600 flex items-center gap-1">
                  <CheckCheck className="w-4 h-4" />
                  Preferences Saved!
                </span>
              ) : (
                <span />
              )}

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setPreferencesOpen(false)}
                  className="px-3.5 py-1.5 text-xs font-semibold text-slate-600 hover:text-slate-800"
                >
                  Close
                </button>
                <button
                  type="button"
                  disabled={prefSaving || !preferences}
                  onClick={handleSavePreferences}
                  className="px-4 py-1.5 text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 rounded-xl shadow-xs transition-colors disabled:opacity-50"
                >
                  {prefSaving ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
