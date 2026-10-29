import http from 'http';
import net from 'net';
import dotenv from 'dotenv';
dotenv.config();

import { env } from './config/env';
import { connectDatabase, disconnectDatabase } from './config/database';
import app from './app';
import { initializeSupportChatSocket, getIO } from './socket/support-chat.socket';

let httpServer: http.Server | null = null;
let isShuttingDown = false;

// ─── Port Probe: Check if a port is already in use ───────────────────────────
function isPortInUse(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        resolve(true);
      } else {
        resolve(false);
      }
    });
    probe.once('listening', () => {
      probe.close(() => resolve(false));
    });
    // Probe on 0.0.0.0 so we detect servers listening on all interfaces
    probe.listen(port, '0.0.0.0');
  });
}

// ─── Graceful Shutdown & Process Lifecycle Management ────────────────────────
export async function gracefulShutdown(signal?: string): Promise<void> {
  if (isShuttingDown) {
    return;
  }
  isShuttingDown = true;

  if (signal) {
    console.log(`[CyberWatch] Received ${signal}. Starting graceful shutdown...`);
  }

  // Safety timer to force exit if closing hangs
  const forceExitTimer = setTimeout(() => {
    console.warn('[CyberWatch] Graceful shutdown timed out. Forcing process exit.');
    process.exit(0);
  }, 4000);
  forceExitTimer.unref();

  // 1. Close Socket.IO instance and disconnect active sockets if initialized
  const io = getIO();
  if (io) {
    try {
      io.disconnectSockets(true);
      await new Promise<void>((resolve) => {
        io.close(() => {
          console.log('[CyberWatch] Socket.IO server closed cleanly.');
          resolve();
        });
      });
    } catch (err) {
      console.error('[CyberWatch] Error closing Socket.IO:', (err as Error).message);
    }
  }

  // 2. Stop HTTP server from accepting new connections and close existing connections
  if (httpServer && httpServer.listening) {
    if (typeof httpServer.closeAllConnections === 'function') {
      httpServer.closeAllConnections();
    }
    await new Promise<void>((resolve) => {
      httpServer!.close((err) => {
        if (err) {
          console.error('[CyberWatch] Error closing HTTP server:', err.message);
        } else {
          console.log('[CyberWatch] HTTP server closed cleanly.');
        }
        resolve();
      });
    });
  }

  // 3. Disconnect Database
  try {
    await disconnectDatabase();
  } catch (err) {
    console.error('[CyberWatch] Error disconnecting MongoDB:', (err as Error).message);
  }

  console.log('[CyberWatch] API process shutdown complete.');

  // Exit cleanly so Nodemon or process manager can proceed immediately
  process.exit(0);
}

// ─── Signal Handlers ──────────────────────────────────────────────────────────
const SHUTDOWN_SIGNALS: NodeJS.Signals[] = ['SIGUSR2', 'SIGINT', 'SIGTERM', 'SIGBREAK', 'SIGHUP'];

SHUTDOWN_SIGNALS.forEach((sig) => {
  process.once(sig, () => {
    gracefulShutdown(sig).catch((err) => {
      console.error(`[CyberWatch] Unhandled error during ${sig} shutdown:`, err);
      process.exit(1);
    });
  });
});

// ─── Duplicate Instance Detection ─────────────────────────────────────────────
// Probe the port BEFORE binding. If already in use, check whether a live
// CyberWatch health endpoint is responding. Either way, exit with code 0
// so nodemon does NOT treat this as a crash and does NOT restart.
async function checkForDuplicateInstance(port: number): Promise<void> {
  const inUse = await isPortInUse(port);
  if (!inUse) return; // Port is free — proceed normally

  // Port is occupied. Try to identify if it is our own CyberWatch API.
  let isCyberWatch = false;
  try {
    const response = await new Promise<string>((resolve, reject) => {
      const req = http.get(
        { hostname: '127.0.0.1', port, path: '/api/v1/health', timeout: 2000 },
        (res) => {
          let body = '';
          res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
          res.on('end', () => resolve(body));
        }
      );
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });
    const parsed = JSON.parse(response) as { service?: string };
    if (parsed.service === 'cyberwatch-api') {
      isCyberWatch = true;
    }
  } catch {
    // Could not reach health endpoint — unknown process on this port
  }

  if (isCyberWatch) {
    console.log(`\n[CyberWatch] ℹ️  CyberWatch API is already running on http://localhost:${port}`);
    console.log(`[CyberWatch] A healthy CyberWatch API instance is already serving requests.`);
    console.log(`[CyberWatch] This duplicate process will exit cleanly. The running instance is unaffected.\n`);
  } else {
    console.error(`\n[CyberWatch] ❌ Port ${port} is already in use by another process.`);
    console.error(`[CyberWatch] CyberWatch API cannot start. Stop the process using port ${port} first.\n`);
  }

  // Exit with code 0 — CRITICAL: this prevents nodemon from treating this
  // as a crash and entering an infinite restart loop.
  process.exit(0);
}

// ─── Server Startup ───────────────────────────────────────────────────────────
async function start() {
  try {
    // ── Step 0: Pre-flight duplicate check ──────────────────────────────────
    // Check port availability before connecting to MongoDB to give the
    // clearest possible diagnostic message and avoid unnecessary DB connections.
    await checkForDuplicateInstance(env.PORT);

    // ── Step 1: Connect to MongoDB ───────────────────────────────────────────
    // Server does NOT start if DB is unavailable.
    await connectDatabase();

    // ── Step 2: Create HTTP server and bind Socket.IO ────────────────────────
    httpServer = http.createServer(app);

    // Secondary EADDRINUSE guard for the rare race-condition where the port
    // becomes occupied between the probe and the actual listen() call.
    httpServer.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`\n[CyberWatch] ❌ Port ${env.PORT} was claimed by another process between startup checks.`);
        console.error(`[CyberWatch] Stop the conflicting process and run 'npm run dev' again.\n`);
        // Exit 0: do NOT let nodemon restart — this would loop forever.
        process.exit(0);
      } else {
        console.error('[CyberWatch] HTTP server error:', err.message);
        process.exit(1);
      }
    });

    initializeSupportChatSocket(httpServer);

    // ── Step 3: Start listening ──────────────────────────────────────────────
    httpServer.listen(env.PORT, () => {
      console.log(`[CyberWatch] API running on http://localhost:${env.PORT}`);
      console.log(`[CyberWatch] Real-time Live Chat Socket.IO initialized`);
      console.log(`[CyberWatch] Environment: ${env.NODE_ENV}`);
      console.log(`[CyberWatch] Frontend URL: ${env.FRONTEND_URL}`);
    });
  } catch (error) {
    console.error('[CyberWatch] Failed to start server:', (error as Error).message);
    process.exit(1);
  }
}

start();

