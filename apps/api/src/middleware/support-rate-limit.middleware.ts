import rateLimit from 'express-rate-limit';

// Ticket creation rate limiter — 10 tickets per 15 minutes per IP/User
export const ticketCreateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many support requests submitted. Please wait before creating another ticket.',
  },
});

// Ticket message replies rate limiter — 30 messages per 15 minutes
export const ticketMessageLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many messages sent. Please slow down.',
  },
});

// Security report rate limiter — 5 reports per 15 minutes
export const securityReportLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many vulnerability reports submitted. Please wait before submitting another report.',
  },
});

// Live chat messages rate limiter — 40 messages per 5 minutes
export const chatMessageLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many chat messages sent. Please wait a moment.',
  },
});

// Attachment upload rate limiter — 20 uploads per 15 minutes
export const attachmentUploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many file uploads requested. Please try again later.',
  },
});
