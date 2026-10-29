import { Schema, model, Document } from 'mongoose';

// ─── User Roles ─────────────────────────────────────────────────────────────
export const USER_ROLES = ['USER', 'ANALYST', 'ADMIN'] as const;
export type UserRole = (typeof USER_ROLES)[number];

// ─── User Document Interface ─────────────────────────────────────────────────
export interface IUser extends Document {
  name: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// ─── User Schema ──────────────────────────────────────────────────────────────
const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [100, 'Name must not exceed 100 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },
    // IMPORTANT: passwordHash only — plain-text passwords are never stored.
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required'],
    },
    role: {
      type: String,
      enum: USER_ROLES,
      default: 'USER',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true, // Automatically manages createdAt and updatedAt
  }
);

// ─── Safe User Projection ────────────────────────────────────────────────────
// Never return passwordHash in API responses. Use this helper to shape
// the user object for client consumption.
export function toSafeUser(user: IUser) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt,
  };
}

export const User = model<IUser>('User', userSchema);
