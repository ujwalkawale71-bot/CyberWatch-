import type { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
import { User } from '../models/User';
import type { UserRole } from '../models/User';

// ─── Augment Express Request ──────────────────────────────────────────────────
// Attach authenticated user info to request object.
declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        role: UserRole;
      };
    }
  }
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
// Reads Authorization header, validates JWT, attaches user to request.
// Never trusts userId or role values provided by the client.
export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        success: false,
        message: 'Authentication required. Please log in.',
      });
      return;
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Authentication token is missing.',
      });
      return;
    }

    // Verify and decode — throws if expired or invalid
    const decoded = verifyToken(token);

    // Verify user still exists and is active in the database
    const user = await User.findById(decoded.userId).select('_id role isActive');

    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'Authentication failed. Account not found or deactivated.',
      });
      return;
    }

    // Attach server-authoritative user info to request
    req.user = {
      userId: user._id.toString(),
      role: user.role,
    };

    next();
  } catch {
    res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token.',
    });
  }
}

// ─── Role-Based Access Control ────────────────────────────────────────────────
// Factory function that creates role-checking middleware.
// Usage: router.get('/admin', requireAuth, requireRole('ADMIN'), handler)
//
// NOTE: requireAuth must be called BEFORE requireRole.
export function requireRole(...roles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required.',
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: 'You do not have permission to access this resource.',
      });
      return;
    }

    next();
  };
}

export async function optionalAuth(
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      if (token) {
        const decoded = verifyToken(token);
        const user = await User.findById(decoded.userId).select('_id role isActive');
        if (user && user.isActive) {
          req.user = {
            userId: user._id.toString(),
            role: user.role,
          };
        }
      }
    }
  } catch {
    // Ignore invalid optional tokens
  }
  next();
}

