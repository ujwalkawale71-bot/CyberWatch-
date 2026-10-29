import { Router } from 'express';
import { supportController } from '../controllers/support.controller';
import { aiSupportController } from '../controllers/ai-support.controller';
import { requireAuth, optionalAuth } from '../middleware/auth.middleware';
import {
  ticketCreateLimiter,
  ticketMessageLimiter,
  securityReportLimiter,
  chatMessageLimiter,
  attachmentUploadLimiter,
} from '../middleware/support-rate-limit.middleware';
import { handleSupportAttachmentUpload } from '../middleware/support-upload.middleware';

const router = Router();

// ─── Support Configuration ───────────────────────────────────────────────────
router.get('/config', supportController.getConfig);

// ─── Support Tickets ─────────────────────────────────────────────────────────
router.post(
  '/tickets',
  requireAuth,
  ticketCreateLimiter,
  handleSupportAttachmentUpload,
  supportController.createTicket
);

router.get('/tickets', requireAuth, supportController.getUserTickets);

router.get('/tickets/:ticketId', requireAuth, supportController.getTicketById);

router.post(
  '/tickets/:ticketId/messages',
  requireAuth,
  ticketMessageLimiter,
  handleSupportAttachmentUpload,
  supportController.addTicketMessage
);

router.post(
  '/tickets/:ticketId/reopen',
  requireAuth,
  supportController.reopenTicket
);

// ─── Attachments ─────────────────────────────────────────────────────────────
router.post(
  '/attachments/upload',
  requireAuth,
  attachmentUploadLimiter,
  handleSupportAttachmentUpload,
  supportController.uploadAttachment
);

router.get(
  '/attachments/:filename',
  optionalAuth,
  supportController.downloadAttachment
);

// ─── Security Vulnerability Reporting ────────────────────────────────────────
router.post(
  '/security-reports',
  optionalAuth,
  securityReportLimiter,
  handleSupportAttachmentUpload,
  supportController.createSecurityReport
);

router.get(
  '/security-reports',
  requireAuth,
  supportController.getUserSecurityReports
);

router.get(
  '/security-reports/:reportId',
  requireAuth,
  supportController.getSecurityReportById
);

// ─── Support Live Chat ───────────────────────────────────────────────────────
router.post(
  '/chat/session',
  optionalAuth,
  supportController.startChatSession
);

router.get(
  '/chat/sessions',
  requireAuth,
  supportController.getUserChatSessions
);

router.get(
  '/chat/session/:sessionId',
  optionalAuth,
  supportController.getChatSession
);

router.post(
  '/chat/session/:sessionId/messages',
  optionalAuth,
  chatMessageLimiter,
  handleSupportAttachmentUpload,
  supportController.sendChatMessage
);

router.post(
  '/chat/session/:sessionId/end',
  optionalAuth,
  supportController.endChatSession
);

router.post(
  '/chat/session/:sessionId/convert-to-ticket',
  requireAuth,
  supportController.convertChatToTicket
);

// ─── Support Operator & Admin Chat Endpoints ─────────────────────────────────
router.get(
  '/admin/chats',
  requireAuth,
  supportController.getOperatorQueue
);

router.post(
  '/admin/chats/:sessionId/claim',
  requireAuth,
  supportController.claimChatSession
);

router.post(
  '/admin/chats/:sessionId/messages',
  requireAuth,
  chatMessageLimiter,
  handleSupportAttachmentUpload,
  supportController.sendOperatorMessage
);

router.post(
  '/admin/chats/:sessionId/close',
  requireAuth,
  supportController.closeOperatorChatSession
);

// ─── AI Support Assistant Endpoints ──────────────────────────────────────────
router.post(
  '/ai/chat',
  optionalAuth,
  chatMessageLimiter,
  aiSupportController.processChat
);

router.get(
  '/ai/quick-actions',
  aiSupportController.getQuickActions
);

router.get(
  '/ai/user-scans',
  requireAuth,
  aiSupportController.getUserScans
);

export default router;

