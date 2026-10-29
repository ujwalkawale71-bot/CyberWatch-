import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

// ─── Protected Route ──────────────────────────────────────────────────────────
// Wraps routes that require authentication.
// - While loading (checking stored token): show a loading indicator
// - If not authenticated: redirect to /login (with return path)
// - If authenticated: render children
export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-slate-500 font-medium">Verifying authentication…</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    // Preserve the attempted path so we can redirect back after login
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
