import mongoose from 'mongoose';
import { env } from './env';

let isConnected = false;

export async function connectDatabase(): Promise<void> {
  if (isConnected) {
    return;
  }

  try {
    const conn = await mongoose.connect(env.MONGODB_URI, {
      // Prevent exposing credentials in logs
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
    });

    isConnected = true;

    if (env.isDev) {
      console.log(`[CyberWatch] MongoDB connected: ${conn.connection.host}`);
    }
  } catch (error) {
    console.error('[CyberWatch] MongoDB connection failed:', (error as Error).message);
    throw error;
  }
}

export async function disconnectDatabase(): Promise<void> {
  if (!isConnected) return;
  await mongoose.disconnect();
  isConnected = false;
  if (env.isDev) {
    console.log('[CyberWatch] MongoDB disconnected.');
  }
}

