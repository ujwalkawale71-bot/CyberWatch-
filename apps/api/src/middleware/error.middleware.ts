import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { env } from '../config/env';

// ─── Application Error ────────────────────────────────────────────────────────
export class AppError extends Error {
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// ─── Global Error Handler ──────────────────────────────────────────────────────
// Must be registered AFTER all other middleware and routes in app.ts.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Log full error in development, minimal in production
  if (env.isDev) {
    console.error('[CyberWatch Error]', err);
  } else {
    console.error('[CyberWatch Error]', err.message);
  }

  // ── Zod Validation Error ──────────────────────────────────────────────────
  if (err instanceof ZodError || err?.name === 'ZodError' || Array.isArray(err?.issues)) {
    const issues = (err as any).issues || (err as any).errors || [];
    const fieldErrors = issues.map((e: any) => ({
      field: Array.isArray(e.path) ? e.path.join('.') : String(e.path || ''),
      message: e.message,
    }));

    res.status(400).json({
      success: false,
      message: 'Validation failed. Please check your input.',
      errors: fieldErrors,
    });
    return;
  }

  // ── Mongoose Duplicate Key Error ──────────────────────────────────────────
  if (err.code === 11000) {
    res.status(409).json({
      success: false,
      message: 'An account with this email already exists.',
    });
    return;
  }

  // ── Mongoose Validation Error ─────────────────────────────────────────────
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e: any) => e.message);
    res.status(400).json({
      success: false,
      message: messages[0] || 'Validation error.',
    });
    return;
  }

  // ── JWT Errors ────────────────────────────────────────────────────────────
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token.',
    });
    return;
  }

  // ── Operational App Errors (AppError) ─────────────────────────────────────
  if (err.isOperational || err.statusCode) {
    res.status(err.statusCode || 400).json({
      success: false,
      message: err.message,
    });
    return;
  }

  // ── Unknown / Unexpected Errors ────────────────────────────────────────────
  // Never expose stack traces or raw error messages to clients in production.
  res.status(500).json({
    success: false,
    message: env.isDev
      ? err.message || 'Internal server error'
      : 'Something went wrong. Please try again later.',
  });
}

// ─── 404 Handler ──────────────────────────────────────────────────────────────
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.path} not found.`,
  });
}
