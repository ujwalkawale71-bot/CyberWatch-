import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 12;

// ─── Hash Password ────────────────────────────────────────────────────────────
// Accepts plain-text password, returns bcrypt hash.
// The plain password is never stored, logged, or returned.
export async function hashPassword(plainPassword: string): Promise<string> {
  return bcrypt.hash(plainPassword, SALT_ROUNDS);
}

// ─── Compare Password ─────────────────────────────────────────────────────────
// Constant-time comparison — safe against timing attacks.
export async function comparePassword(
  plainPassword: string,
  passwordHash: string
): Promise<boolean> {
  return bcrypt.compare(plainPassword, passwordHash);
}
