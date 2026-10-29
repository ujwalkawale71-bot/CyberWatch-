import { User, toSafeUser } from '../models/User';
import { hashPassword, comparePassword } from '../utils/password';
import { signToken } from '../utils/jwt';
import type { RegisterInput, LoginInput } from '../schemas/auth.schema';

// ─── Auth Service ─────────────────────────────────────────────────────────────
// Contains all business logic for authentication.
// Controllers call these methods and handle HTTP-level concerns.

export const authService = {
  // ── Register ────────────────────────────────────────────────────────────────
  async register(input: RegisterInput) {
    const { name, email, password } = input;

    // Check for existing email (case-insensitive via Mongoose lowercase option)
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      const error = new Error('An account with this email already exists.');
      (error as any).statusCode = 409;
      throw error;
    }

    // Hash password — plain password is discarded after this point
    const passwordHash = await hashPassword(password);

    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      passwordHash,
      role: 'USER',
      isActive: true,
    });

    const token = signToken({ userId: user._id.toString(), role: user.role });

    return {
      user: toSafeUser(user),
      token,
    };
  },

  // ── Login ────────────────────────────────────────────────────────────────────
  async login(input: LoginInput) {
    const { email, password } = input;

    // Find user — generic error message regardless of whether email exists
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user || !user.isActive) {
      // Generic message — do not reveal whether email exists
      const error = new Error('Invalid email or password.');
      (error as any).statusCode = 401;
      throw error;
    }

    const passwordMatch = await comparePassword(password, user.passwordHash);
    if (!passwordMatch) {
      // Generic message — do not reveal which field is wrong
      const error = new Error('Invalid email or password.');
      (error as any).statusCode = 401;
      throw error;
    }

    const token = signToken({ userId: user._id.toString(), role: user.role });

    return {
      user: toSafeUser(user),
      token,
    };
  },

  // ── Get User by ID ─────────────────────────────────────────────────────────
  async getUserById(userId: string) {
    const user = await User.findById(userId).select('-passwordHash');
    if (!user || !user.isActive) {
      const error = new Error('User not found.');
      (error as any).statusCode = 404;
      throw error;
    }
    return toSafeUser(user);
  },
};
