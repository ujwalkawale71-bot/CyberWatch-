import dotenv from 'dotenv';
dotenv.config();

// ─── Environment Configuration ─────────────────────────────────────────────
// Validates and exports required environment variables at startup.
// The server will NOT start if critical variables are missing.

function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value || value.trim() === '') {
    throw new Error(`[CyberWatch] Missing required environment variable: ${key}`);
  }
  return value.trim();
}

function getEnv(key: string, fallback: string): string {
  return process.env[key]?.trim() || fallback;
}

export const env = {
  NODE_ENV: getEnv('NODE_ENV', 'development'),
  PORT: parseInt(getEnv('PORT', '5000'), 10),
  MONGODB_URI: getEnv('MONGODB_URI', 'mongodb://localhost:27017/cyberwatch'),
  JWT_SECRET: (() => {
    // In production, JWT_SECRET is strictly required.
    // In development, we allow a fallback but log a warning.
    const secret = process.env.JWT_SECRET?.trim();
    if (!secret || secret === '') {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('[CyberWatch] JWT_SECRET is required in production.');
      }
      console.warn('[CyberWatch] WARNING: JWT_SECRET not set. Using insecure development default. DO NOT use in production.');
      return 'dev-insecure-jwt-secret-change-me-in-production';
    }
    return secret;
  })(),
  JWT_EXPIRES_IN: getEnv('JWT_EXPIRES_IN', '7d'),
  FRONTEND_URL: getEnv('FRONTEND_URL', 'http://localhost:5173'),
  isDev: getEnv('NODE_ENV', 'development') === 'development',
  isProd: getEnv('NODE_ENV', 'development') === 'production',
  FILE_SCAN_MAX_SIZE_MB: parseInt(getEnv('FILE_SCAN_MAX_SIZE_MB', '25'), 10) || 25,
  FILE_SCAN_RATE_LIMIT: parseInt(getEnv('FILE_SCAN_RATE_LIMIT', '5'), 10) || 5,
  FILE_SCAN_RATE_WINDOW_SECONDS: parseInt(getEnv('FILE_SCAN_RATE_WINDOW_SECONDS', '60'), 10) || 60,
  VIRUSTOTAL_API_KEY: getEnv('VIRUSTOTAL_API_KEY', ''),
  ABUSEIPDB_API_KEY: getEnv('ABUSEIPDB_API_KEY', ''),
  OTX_API_KEY: getEnv('OTX_API_KEY', ''),
  URLHAUS_API_KEY: getEnv('URLHAUS_API_KEY', ''),
  MALWAREBAZAAR_API_KEY: getEnv('MALWAREBAZAAR_API_KEY', ''),
  HYBRID_ANALYSIS_API_KEY: getEnv('HYBRID_ANALYSIS_API_KEY', ''),
  GOOGLE_WEB_RISK_API_KEY: getEnv('GOOGLE_WEB_RISK_API_KEY', ''),
  GOOGLE_SAFE_BROWSING_API_KEY: getEnv('GOOGLE_SAFE_BROWSING_API_KEY', ''),
  THREAT_INTELLIGENCE_CACHE_TTL_SECONDS: parseInt(getEnv('THREAT_INTELLIGENCE_CACHE_TTL_SECONDS', '3600'), 10) || 3600,
  SUPPORT_EMAIL: getEnv('SUPPORT_EMAIL', ''),
  SECURITY_EMAIL: getEnv('SECURITY_EMAIL', ''),
  SUPPORT_PHONE: getEnv('SUPPORT_PHONE', ''),
  SUPPORT_WHATSAPP: getEnv('SUPPORT_WHATSAPP', ''),
  SUPPORT_LIVE_CHAT_ENABLED: getEnv('SUPPORT_LIVE_CHAT_ENABLED', 'true') !== 'false',
  SUPPORT_HOURS: getEnv('SUPPORT_HOURS', '24/7'),
  SUPPORT_ATTACHMENT_MAX_SIZE_MB: parseInt(getEnv('SUPPORT_ATTACHMENT_MAX_SIZE_MB', '10'), 10) || 10,
  SMTP_HOST: getEnv('SMTP_HOST', ''),
  SMTP_PORT: parseInt(getEnv('SMTP_PORT', '587'), 10) || 587,
  SMTP_USER: getEnv('SMTP_USER', ''),
  SMTP_PASS: getEnv('SMTP_PASS', ''),
  SMTP_FROM: getEnv('SMTP_FROM', ''),
  AI_API_KEY: getEnv('AI_API_KEY', process.env.OPENAI_API_KEY?.trim() || ''),
  AI_PROVIDER: getEnv('AI_PROVIDER', ''),
  AI_SERVICE_URL: getEnv('AI_SERVICE_URL', 'http://localhost:8000'),
  OPENAI_API_KEY: getEnv('OPENAI_API_KEY', ''),
  GEMINI_API_KEY: getEnv('GEMINI_API_KEY', ''),
  ANTHROPIC_API_KEY: getEnv('ANTHROPIC_API_KEY', ''),
  AI_MODEL: getEnv('AI_MODEL', 'gpt-4o-mini'),
} as const;


