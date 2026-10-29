import jwt from 'jsonwebtoken';
import { env } from '../config/env';
import type { UserRole } from '../models/User';

// ─── JWT Payload ──────────────────────────────────────────────────────────────
// Keep the payload minimal — only what is needed for authorization.
// Never include passwords, personal data, or sensitive information.
export interface JwtPayload {
  userId: string;
  role: UserRole;
}

// ─── Sign Token ───────────────────────────────────────────────────────────────
export function signToken(payload: JwtPayload): string {
  return jwt.sign(payload, env.JWT_SECRET, {
    expiresIn: env.JWT_EXPIRES_IN,
  } as jwt.SignOptions);
}

// ─── Verify Token ─────────────────────────────────────────────────────────────
export function verifyToken(token: string): JwtPayload {
  const decoded = jwt.verify(token, env.JWT_SECRET);
  return decoded as JwtPayload;
}
