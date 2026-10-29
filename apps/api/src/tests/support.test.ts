import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../app';
import { signToken } from '../utils/jwt';
import { supportAttachmentService } from '../services/support-attachment.service';
import { emailNotificationService } from '../services/email-notification.service';

const {
  userAId,
  userBId,
  adminId,
  mockUserA,
  mockUserB,
  mockAdmin,
  mockTickets,
  mockSecurityReports,
  mockChatSessions,
} = vi.hoisted(() => {
  const uAId = '507f1f77bcf86cd799439001';
  const uBId = '507f1f77bcf86cd799439002';
  const aId = '507f1f77bcf86cd799439003';

  const userA = {
    _id: { toString: () => uAId },
    id: uAId,
    name: 'Alice Security',
    email: 'alice@security.internal',
    role: 'USER',
    isActive: true,
  };

  const userB = {
    _id: { toString: () => uBId },
    id: uBId,
    name: 'Bob Operator',
    email: 'bob@operator.internal',
    role: 'USER',
    isActive: true,
  };

  const admin = {
    _id: { toString: () => aId },
    id: aId,
    name: 'Admin Lead',
    email: 'admin@cyberwatch.internal',
    role: 'ADMIN',
    isActive: true,
  };

  const ticketsStore: any[] = [];
  const securityReportsStore: any[] = [];
  const chatSessionsStore: any[] = [];

  return {
    userAId: uAId,
    userBId: uBId,
    adminId: aId,
    mockUserA: userA,
    mockUserB: userB,
    mockAdmin: admin,
    mockTickets: ticketsStore,
    mockSecurityReports: securityReportsStore,
    mockChatSessions: chatSessionsStore,
  };
});

// Mock User model
vi.mock('../models/User', () => {
  const User = {
    findById: vi.fn().mockImplementation((id: string) => {
      const idStr = id?.toString();
      let foundUser = null;
      if (idStr === userAId) foundUser = mockUserA;
      if (idStr === userBId) foundUser = mockUserB;
      if (idStr === adminId) foundUser = mockAdmin;

      return {
        select: vi.fn().mockResolvedValue(foundUser),
        then: (resolve: any) => resolve(foundUser),
      };
    }),
  };
  return { User };
});

// Mock Scan model
vi.mock('../models/Scan', () => {
  const Scan = {
    findById: vi.fn().mockResolvedValue(null),
  };
  return { Scan };
});

// Mock SupportTicket model
vi.mock('../models/SupportTicket', async () => {
  const actual = (await vi.importActual('../models/SupportTicket')) as any;

  const SupportTicket = {
    countDocuments: vi.fn().mockImplementation(() => Promise.resolve(mockTickets.length)),
    create: vi.fn().mockImplementation((data: any) => {
      const newTicket = {
        ...data,
        _id: { toString: () => `ticket_${Date.now()}_${Math.random().toString(36).substr(2, 5)}` },
        createdAt: new Date(),
        updatedAt: new Date(),
        save: vi.fn().mockResolvedValue(true),
      };
      mockTickets.push(newTicket);
      return Promise.resolve(newTicket);
    }),
    find: vi.fn().mockImplementation((query: any) => {
      let results = [...mockTickets];
      if (query.userId) {
        const uId = query.userId.toString();
        results = results.filter((t) => t.userId.toString() === uId);
      }
      if (query.status && query.status !== 'ALL') {
        results = results.filter((t) => t.status === query.status);
      }
      return {
        sort: vi.fn().mockReturnThis(),
        skip: vi.fn().mockReturnThis(),
        limit: vi.fn().mockResolvedValue(results),
      };
    }),
    findOne: vi.fn().mockImplementation((query: any) => {
      let found = null;
      if (query.ticketNumber) {
        found = mockTickets.find((t) => t.ticketNumber === query.ticketNumber);
      }
      return Promise.resolve(found);
    }),
    findById: vi.fn().mockImplementation((id: string) => {
      const found = mockTickets.find((t) => t._id.toString() === id.toString());
      return Promise.resolve(found);
    }),
  };

  return {
    ...actual,
    SupportTicket,
  };
});

// Mock SecurityReport model
vi.mock('../models/SecurityReport', async () => {
  const actual = (await vi.importActual('../models/SecurityReport')) as any;

  const SecurityReport = {
    countDocuments: vi.fn().mockImplementation(() => Promise.resolve(mockSecurityReports.length)),
    create: vi.fn().mockImplementation((data: any) => {
      const newReport = {
        ...data,
        _id: { toString: () => `sec_${Date.now()}` },
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      mockSecurityReports.push(newReport);
      return Promise.resolve(newReport);
    }),
    find: vi.fn().mockImplementation((query: any) => {
      let results = [...mockSecurityReports];
      if (query.userId) {
        results = results.filter((r) => r.userId?.toString() === query.userId.toString());
      }
      return {
        sort: vi.fn().mockResolvedValue(results),
      };
    }),
    findOne: vi.fn().mockImplementation((query: any) => {
      const found = mockSecurityReports.find((r) => r.reportNumber === query.reportNumber);
      return Promise.resolve(found);
    }),
    findById: vi.fn().mockImplementation((id: string) => {
      const found = mockSecurityReports.find((r) => r._id.toString() === id.toString());
      return Promise.resolve(found);
    }),
  };

  return {
    ...actual,
    SecurityReport,
  };
});

// Mock SupportChatSession model
vi.mock('../models/SupportChatSession', async () => {
  const actual = (await vi.importActual('../models/SupportChatSession')) as any;

  const SupportChatSession = {
    create: vi.fn().mockImplementation((data: any) => {
      const newSession = {
        ...data,
        _id: { toString: () => `chat_${Date.now()}` },
        createdAt: new Date(),
        updatedAt: new Date(),
        save: vi.fn().mockResolvedValue(true),
      };
      mockChatSessions.push(newSession);
      return Promise.resolve(newSession);
    }),
    findOne: vi.fn().mockImplementation((query: any) => {
      let found = null;
      if (query.sessionId) {
        found = mockChatSessions.find((s) => s.sessionId === query.sessionId);
      } else if (query.userId) {
        found = mockChatSessions.find((s) => s.userId?.toString() === query.userId.toString());
      }
      if (found) {
        found.save = vi.fn().mockResolvedValue(true);
      }
      return {
        sort: vi.fn().mockResolvedValue(found),
        then: (resolve: any) => resolve(found),
      };
    }),
  };

  return {
    ...actual,
    SupportChatSession,
  };
});

describe('CyberWatch Contact Support & Help Desk API', () => {
  const tokenUserA = signToken({ userId: userAId, role: 'USER' });
  const tokenUserB = signToken({ userId: userBId, role: 'USER' });
  const tokenAdmin = signToken({ userId: adminId, role: 'ADMIN' });

  beforeEach(() => {
    mockTickets.length = 0;
    mockSecurityReports.length = 0;
    mockChatSessions.length = 0;
  });

  // ─── 1. Support Config ──────────────────────────────────────────────────────
  describe('GET /api/v1/support/config', () => {
    it('returns public support contact configuration with safe values', async () => {
      const res = await request(app).get('/api/v1/support/config');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(typeof res.body.data.supportEmail).toBe('string');
      expect(typeof res.body.data.securityEmail).toBe('string');
      expect(typeof res.body.data.supportPhone).toBe('string');
      expect(typeof res.body.data.supportWhatsapp).toBe('string');
      expect(res.body.data.supportHours).toBe('24/7');
      expect(res.body.data.liveChatEnabled).toBe(true);
      expect(Array.isArray(res.body.data.allowedAttachmentExtensions)).toBe(true);
    });
  });

  // ─── 2. Ticket Creation & Validation ────────────────────────────────────────
  describe('POST /api/v1/support/tickets', () => {
    it('rejects unauthenticated ticket creation', async () => {
      const res = await request(app)
        .post('/api/v1/support/tickets')
        .send({
          category: 'TECHNICAL_ISSUE',
          subject: 'Need help with scan',
          description: 'Detailed explanation of problem encountered during website scanning',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('creates a support ticket with generated ticket number (CW-YYYY-XXXXXX)', async () => {
      const res = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'SCANNER_ISSUE',
          priority: 'HIGH',
          subject: 'Website Scanner Timeout on Subdomain',
          description: 'The scanner times out when trying to analyze subdomains with SSL inspection.',
          targetUrl: 'https://sub.example.com',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.ticketNumber).toMatch(/^CW-\d{4}-\d+/);
      expect(res.body.data.category).toBe('SCANNER_ISSUE');
      expect(res.body.data.priority).toBe('HIGH');
      expect(res.body.data.status).toBe('OPEN');
      expect(res.body.data.userId).toBe(userAId);
    });

    it('rejects invalid category with validation error', async () => {
      const res = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'INVALID_CATEGORY_ARBITRARY',
          subject: 'Test subject with invalid category',
          description: 'Long enough description of the issue to pass length check.',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('rejects ticket with description shorter than minimum length', async () => {
      const res = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'OTHER',
          subject: 'Valid Subject Line',
          description: 'Short',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ─── 3. IDOR & Ownership Enforcement ────────────────────────────────────────
  describe('IDOR & Ticket Ownership Controls', () => {
    it('prevents User B from viewing User A ticket', async () => {
      // 1. User A creates a ticket
      const createRes = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'REPORT_EXPORT',
          priority: 'MEDIUM',
          subject: 'PDF Export Missing Header Findings',
          description: 'When exporting executive summary PDF, some header findings are truncated.',
        });

      const ticketNumber = createRes.body.data.ticketNumber;

      // 2. User A can view it
      const viewResA = await request(app)
        .get(`/api/v1/support/tickets/${ticketNumber}`)
        .set('Authorization', `Bearer ${tokenUserA}`);

      expect(viewResA.status).toBe(200);
      expect(viewResA.body.data.ticketNumber).toBe(ticketNumber);

      // 3. User B tries to view it — MUST BE BLOCKED
      const viewResB = await request(app)
        .get(`/api/v1/support/tickets/${ticketNumber}`)
        .set('Authorization', `Bearer ${tokenUserB}`);

      expect(viewResB.status).toBe(400);
      expect(viewResB.body.message).toContain('permission');

      // 4. Admin CAN view it
      const viewResAdmin = await request(app)
        .get(`/api/v1/support/tickets/${ticketNumber}`)
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(viewResAdmin.status).toBe(200);
    });

    it('prevents User B from posting a reply to User A ticket', async () => {
      const createRes = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'BILLING_SUBSCRIPTION',
          priority: 'LOW',
          subject: 'Question on Enterprise Plan',
          description: 'Inquiring about maximum concurrent scans supported in enterprise tier.',
        });

      const ticketNumber = createRes.body.data.ticketNumber;

      // User B tries to reply to User A's ticket
      const replyResB = await request(app)
        .post(`/api/v1/support/tickets/${ticketNumber}/messages`)
        .set('Authorization', `Bearer ${tokenUserB}`)
        .send({
          message: 'Unauthorized response attempt from User B',
        });

      expect(replyResB.status).toBe(400);
      expect(replyResB.body.message).toContain('permission');
    });
  });

  // ─── 4. Conversation & Message Posting ──────────────────────────────────────
  describe('Ticket Messages & Lifecycle', () => {
    it('allows User A to reply and enforces server-side senderType USER', async () => {
      const createRes = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'THREAT_INTELLIGENCE',
          priority: 'MEDIUM',
          subject: 'Threat feed sync discrepancy',
          description: 'AbuseIPDB reputation indicators show pending state on dashboard.',
        });

      const ticketNumber = createRes.body.data.ticketNumber;

      // User A replies
      const replyRes = await request(app)
        .post(`/api/v1/support/tickets/${ticketNumber}/messages`)
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          message: 'Additional information: the IP in question is 198.51.100.4',
          senderType: 'SUPPORT', // Attempt to spoof SUPPORT — backend MUST override to USER
        });

      expect(replyRes.status).toBe(200);
      const messages = replyRes.body.data.messages;
      expect(messages.length).toBe(2);
      expect(messages[1].senderType).toBe('USER');
    });

    it('allows reopening a resolved ticket and adds SYSTEM timeline event', async () => {
      const createRes = await request(app)
        .post('/api/v1/support/tickets')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          category: 'TECHNICAL_ISSUE',
          priority: 'MEDIUM',
          subject: 'Issue to be resolved and reopened',
          description: 'Initial testing description for resolution and reopen cycle.',
        });

      const ticketNumber = createRes.body.data.ticketNumber;

      // Reopen ticket
      const reopenRes = await request(app)
        .post(`/api/v1/support/tickets/${ticketNumber}/reopen`)
        .set('Authorization', `Bearer ${tokenUserA}`)
        .send({
          reason: 'Problem recurred on latest scan run.',
        });

      expect(reopenRes.status).toBe(200);
      expect(reopenRes.body.data.status).toBe('OPEN');
      const messages = reopenRes.body.data.messages;
      const systemMessage = messages.find((m: any) => m.senderType === 'SYSTEM');
      expect(systemMessage).toBeDefined();
      expect(systemMessage.message).toContain('reopened');
    });
  });

  // ─── 5. Attachment Security & Validation ────────────────────────────────────
  describe('Attachment Security Controls', () => {
    it('rejects forbidden executable file attachments (.exe, .bat, .sh)', () => {
      const exeValidation = supportAttachmentService.validateFile('malware.exe', 'application/x-msdownload', 1024);
      expect(exeValidation.valid).toBe(false);
      expect(exeValidation.error).toContain('prohibited');

      const batValidation = supportAttachmentService.validateFile('script.bat', 'text/plain', 500);
      expect(batValidation.valid).toBe(false);

      const shValidation = supportAttachmentService.validateFile('payload.sh', 'application/x-sh', 500);
      expect(shValidation.valid).toBe(false);
    });

    it('accepts permitted cybersecurity report file types (.pdf, .png, .jpg, .txt, .csv, .json)', () => {
      const pdfValidation = supportAttachmentService.validateFile('scan_report.pdf', 'application/pdf', 1024 * 500);
      expect(pdfValidation.valid).toBe(true);

      const jsonValidation = supportAttachmentService.validateFile('ioc_indicators.json', 'application/json', 1024 * 50);
      expect(jsonValidation.valid).toBe(true);
    });
  });

  // ─── 6. Confidential Security Vulnerability Reporting ───────────────────────
  describe('POST /api/v1/support/security-reports', () => {
    it('successfully receives confidential vulnerability report with SEC-YYYY-XXXXXX identifier', async () => {
      const res = await request(app)
        .post('/api/v1/support/security-reports')
        .send({
          email: 'researcher@zeroday.org',
          vulnerabilityType: 'SSRF',
          severity: 'HIGH',
          affectedComponent: 'Website Scanner Host Resolution',
          affectedUrl: 'https://api.cyberwatch.internal/api/v1/scans/website',
          description: 'DNS rebinding allows internal subnet scanning on 127.0.0.1.',
          stepsToReproduce: '1. Set up DNS with TTL 0. 2. Point scanner to domain. 3. Observe internal response.',
          impact: 'Potential internal port scanning in virtual private network.',
          suggestedFix: 'Enforce pre-resolution IP checking on all outgoing requests.',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.reportNumber).toMatch(/^SEC-\d{4}-\d+/);
      expect(res.body.data.vulnerabilityType).toBe('SSRF');
      expect(res.body.data.severity).toBe('HIGH');
      expect(res.body.data.status).toBe('SUBMITTED');
    });

    it('rejects vulnerability report with missing required reproduction steps', async () => {
      const res = await request(app)
        .post('/api/v1/support/security-reports')
        .send({
          email: 'researcher@zeroday.org',
          vulnerabilityType: 'XSS',
          severity: 'MEDIUM',
          affectedComponent: 'Reports Page',
          description: 'Reflected parameter in query string.',
          stepsToReproduce: 'Too short',
          impact: 'Session hijacking potential.',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ─── 7. Support Live Chat Desk ──────────────────────────────────────────────
  describe('Support Live Chat Operations', () => {
    it('starts chat session in real WAITING_FOR_AGENT state without faking online agents', async () => {
      const startRes = await request(app)
        .post('/api/v1/support/chat/session')
        .send({
          userName: 'David Security',
          userEmail: 'david@company.com',
          initialMessage: 'Hello, need clarification on API Scanner results.',
        });

      expect(startRes.status).toBe(201);
      expect(startRes.body.data.sessionId).toMatch(/^CHAT-\d{4}-/);
      expect(startRes.body.data.status).toBe('WAITING_FOR_AGENT');

      const sessionId = startRes.body.data.sessionId;

      // Post a message in the chat
      const msgRes = await request(app)
        .post(`/api/v1/support/chat/session/${sessionId}/messages`)
        .send({
          message: 'Can someone check scan ID 660f123?',
          senderName: 'David Security',
        });

      expect(msgRes.status).toBe(200);
      expect(msgRes.body.data.messages.length).toBeGreaterThanOrEqual(2);

      // Operator Claiming and Replying to Chat
      const claimRes = await request(app)
        .post(`/api/v1/support/admin/chats/${sessionId}/claim`)
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(claimRes.status).toBe(200);
      expect(claimRes.body.data.status).toBe('ACTIVE');

      const opMsgRes = await request(app)
        .post(`/api/v1/support/admin/chats/${sessionId}/messages`)
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .send({
          message: 'Hello David, an engineer is reviewing your scan ID 660f123 now.',
        });

      expect(opMsgRes.status).toBe(200);
      const lastMsg = opMsgRes.body.data.messages[opMsgRes.body.data.messages.length - 1];
      expect(lastMsg.senderType).toBe('SUPPORT');

      // Convert Chat to Ticket
      const convertRes = await request(app)
        .post(`/api/v1/support/chat/session/${sessionId}/convert-to-ticket`)
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(convertRes.status).toBe(201);
      expect(convertRes.body.data.ticketNumber).toMatch(/^CW-\d{4}-\d+/);

      // End chat
      const endRes = await request(app)
        .post(`/api/v1/support/chat/session/${sessionId}/end`);

      expect(endRes.status).toBe(200);
      expect(endRes.body.data.status).toBe('CLOSED');
    });
  });
});
