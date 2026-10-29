import { env } from '../config/env';
import { Scan } from '../models/Scan';
import { AppError } from '../middleware/error.middleware';
import type {
  AISupportChatRequest,
  AISupportChatResponse,
  AISupportQuickAction,
} from '@cyberwatch/shared';

// ─── Grounded Platform Knowledge Base ─────────────────────────────────────────

const CYBERWATCH_KNOWLEDGE_BASE = {
  scanners: {
    urlPhishing: {
      name: 'URL & Phishing Mega Scanner',
      slug: 'url-phishing',
      endpoint: '/services/url-phishing',
      description: 'Unified analysis of URLs, domains, DNS records, redirect hops, page structure, and phishing threat indicators.',
      capabilities: [
        'Multi-hop HTTP/HTTPS redirect journey analysis and protocol downgrade detection',
        'Punycode and homograph attack detection (IDN spoofing)',
        'Domain age, entropy, IP reputation, and suspicious URL pattern detection',
        'Live TLS certificate validation, expiration monitoring, and cipher suite auditing',
        'Direct IP and custom port exposure checks',
      ],
    },
    websiteScanner: {
      name: 'Website Security Scanner V2',
      slug: 'website-scanner',
      endpoint: '/services/website-scanner',
      description: 'Evidence-based audit of website posture, HTTP security headers, cookies, scripts, forms, and TLS configurations.',
      capabilities: [
        'Security header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)',
        'Cookie security audit (Secure, HttpOnly, SameSite attributes, sensitive plaintext storage)',
        'Form security and password field posture (plaintext actions, cross-domain submissions)',
        'Mixed content detection (HTTP resources loaded over HTTPS)',
        'Server software and technology stack fingerprinting with error leakage checks',
      ],
    },
    apiScanner: {
      name: 'API Security Scanner',
      slug: 'api-scanner',
      endpoint: '/services/api-scanner',
      description: 'Audits REST and GraphQL API endpoints for CORS misconfigurations, authentication schemes, information disclosure, and rate limiting.',
      capabilities: [
        'CORS policy analysis (Wildcard origins with credentials, permissive headers)',
        'Authentication indicator verification (Bearer, API Key, Basic, OAuth)',
        'Rate limit telemetry inspection (X-RateLimit-Limit, Remaining, Reset headers)',
        'Information disclosure audit (Server versions, debug stacks, exposed internal tokens)',
      ],
    },
    fileScanner: {
      name: 'File Security Scanner',
      slug: 'file',
      endpoint: '/services/file',
      description: 'Multi-stage static analysis of downloadable files, binaries, archives, and documents.',
      capabilities: [
        'Cryptographic hashing (MD5, SHA-1, SHA-256, SSDeep fuzzy hashing)',
        'Multi-provider malware reputation check (VirusTotal, MalwareBazaar, Hybrid Analysis)',
        'MIME type vs claimed extension masquerading detection',
        'Shannon entropy computation for packed or encrypted payloads',
        'YARA signature scanning and suspicious string/command extraction',
        'Format-specific parsing for PE executables, PDFs, Office macros, Archives, and Scripts',
      ],
    },
    extensionScanner: {
      name: 'Browser Extension Scanner',
      slug: 'extension',
      endpoint: '/services/extension',
      description: 'Audits Chrome Web Store and Firefox extensions for excessive permissions and malicious JavaScript patterns.',
      capabilities: [
        'Manifest V2/V3 privilege analysis (high-risk permissions: <all_urls>, webRequestBlocking, nativeMessaging, debugger)',
        'JavaScript AST and regex inspection for eval(), new Function(), and obfuscated payloads',
        'Web Store reputation and verified developer telemetry verification',
        'Network telemetry detection for covert external data exfiltration',
      ],
    },
  },
  riskScoring: {
    scale: '0 to 100 (Higher score = higher security risk)',
    classifications: [
      { score: '0 - 19', level: 'Safe', description: 'Clean posture with robust security controls and zero confirmed threats.' },
      { score: '20 - 39', level: 'Low Risk', description: 'Minor security weaknesses or hardening opportunities detected.' },
      { score: '40 - 69', level: 'Suspicious', description: 'Significant configuration gaps or suspicious indicators requiring remediation.' },
      { score: '70 - 89', level: 'High Risk', description: 'High-severity security risks, insecure data handling, or strong threat indicators.' },
      { score: '90 - 100', level: 'Critical', description: 'Confirmed malicious threat, active phishing, or critical vulnerability requiring immediate remediation.' },
    ],
  },
  threatIntel: {
    sources: ['AbuseIPDB', 'VirusTotal', 'AlienVault OTX', 'URLhaus', 'MalwareBazaar', 'CISA Advisories'],
    types: ['IPv4/IPv6 Reputation', 'Domain Reputation', 'File Hashes', 'Threat Feeds', 'CVE Advisories'],
  },
  supportSla: {
    hours: '24/7 Monitoring & Technical Support Desk',
    channels: ['Live Operator Support Chat', 'Support Ticket Desk', 'Confidential Vulnerability Reporting'],
  },
};

// ─── Quick Actions ─────────────────────────────────────────────────────────────

export const AI_QUICK_ACTIONS: AISupportQuickAction[] = [
  {
    id: 'explain-scan',
    title: 'Explain My Scan',
    description: 'Break down your latest security scan results and risk contributors.',
    prompt: 'Can you explain the security findings and risk score from my latest scan?',
    category: 'scans',
    icon: 'Activity',
  },
  {
    id: 'why-risk-high',
    title: 'Why Is My Risk Score High?',
    description: 'Understand the specific vulnerabilities driving up your risk score.',
    prompt: 'Why is my scan risk score high and what are the top findings I should fix first?',
    category: 'findings',
    icon: 'AlertTriangle',
  },
  {
    id: 'threat-intel',
    title: 'Threat Intelligence Help',
    description: 'Learn how IOC reputation and threat indicators affect your assets.',
    prompt: 'How does CyberWatch correlate threat intelligence and reputation feeds?',
    category: 'threat_intel',
    icon: 'Globe',
  },
  {
    id: 'troubleshoot',
    title: 'Scanner Troubleshooting',
    description: 'Get help with unreachable targets, timeouts, or policy blocks.',
    prompt: 'My scan failed or returned unreachable. How can I troubleshoot this?',
    category: 'troubleshooting',
    icon: 'HelpCircle',
  },
  {
    id: 'talk-human',
    title: 'Talk to Human Support',
    description: 'Connect with a live CyberWatch security engineer or open a ticket.',
    prompt: 'I need to speak with a human support specialist about my account or a critical issue.',
    category: 'escalation',
    icon: 'Headphones',
  },
];

export const aiSupportService = {
  /**
   * Get available quick actions.
   */
  getQuickActions(): AISupportQuickAction[] {
    return AI_QUICK_ACTIONS;
  },

  /**
   * Fetch recent scans for authenticated user to populate the AI context selector.
   */
  async getUserScansForAI(userId: string) {
    const scans = await Scan.find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .select('_id target targetType result riskScore createdAt findings');

    return scans.map((s) => ({
      id: s._id.toString(),
      target: s.target,
      targetType: s.targetType,
      riskScore: s.riskScore,
      riskLevel: s.result || 'Safe',
      findingsCount: s.findings?.length || 0,
      createdAt: s.createdAt.toISOString(),
    }));
  },

  /**
   * Main AI Support Chat Handler.
   */
  async processAIChat(
    userId: string | undefined,
    request: AISupportChatRequest
  ): Promise<AISupportChatResponse> {
    const message = (request.message || '').trim();
    if (!message) {
      throw new AppError('Message is required.', 400);
    }
    if (message.length > 4000) {
      throw new AppError('Message exceeds maximum allowed length of 4000 characters.', 400);
    }

    const conversationId =
      request.conversationId || `conv_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    // 1. Check for human escalation keywords
    const lower = message.toLowerCase();
    const isEscalationIntent =
      lower.includes('human') ||
      lower.includes('speak to someone') ||
      lower.includes('talk to an agent') ||
      lower.includes('support operator') ||
      lower.includes('billing') ||
      lower.includes('refund') ||
      lower.includes('vulnerability report') ||
      lower.includes('critical emergency');

    // 2. Fetch authorized scan context if scanId or direct scanContext is provided
    let scanContext: AISupportChatResponse['scanContext'] | undefined;
    let scanDataForPrompt: any = null;

    if (request.scanId) {
      if (!userId) {
        throw new AppError('Authentication required to analyze user scans.', 401);
      }

      const scan = await Scan.findById(request.scanId);
      if (!scan) {
        throw new AppError('Scan not found.', 404);
      }

      // Strict Ownership / IDOR Check
      if (scan.userId && scan.userId.toString() !== userId) {
        throw new AppError('You do not have permission to access this scan context.', 403);
      }

      scanContext = {
        scanId: scan._id.toString(),
        target: scan.target,
        targetType: scan.targetType,
        riskScore: scan.riskScore,
        riskLevel: scan.result || 'Safe',
        findingsCount: scan.findings?.length || 0,
      };

      scanDataForPrompt = {
        scanId: scan._id.toString(),
        target: scan.target,
        targetType: scan.targetType,
        riskScore: scan.riskScore,
        riskLevel: scan.result || 'Safe',
        findings: scan.findings?.slice(0, 10).map((f) => ({
          title: f.title,
          severity: f.severity,
          description: f.description,
          recommendation: f.recommendation,
        })),
        checks: scan.checks,
      };
    } else if (request.scanContext && request.scanContext.target) {
      scanContext = {
        scanId: request.scanContext.scanId,
        target: request.scanContext.target,
        targetType: request.scanContext.targetType || 'URL',
        riskScore: request.scanContext.riskScore ?? 0,
        riskLevel: request.scanContext.riskLevel || request.scanContext.verdict || 'Safe',
        findingsCount:
          request.scanContext.findingsCount ??
          (request.scanContext.findings ? request.scanContext.findings.length : 0),
      };

      scanDataForPrompt = {
        scanId: request.scanContext.scanId,
        target: request.scanContext.target,
        targetType: request.scanContext.targetType,
        riskScore: request.scanContext.riskScore,
        riskLevel: request.scanContext.riskLevel || request.scanContext.verdict,
        verdict: request.scanContext.verdict,
        findings: request.scanContext.findings,
        evidence: request.scanContext.evidence,
        recommendations: request.scanContext.recommendations,
        threatIntelligence: request.scanContext.threatIntelligence,
        domainIntelligence: request.scanContext.domainIntelligence,
        httpTlsInfo: request.scanContext.httpTlsInfo,
        phishingFindings: request.scanContext.phishingFindings,
        extensionFindings: request.scanContext.extensionFindings,
        fileFindings: request.scanContext.fileFindings,
      };
    }

    // 3. Isolated AI Service Integration (FastAPI microservice at env.AI_SERVICE_URL)
    if (env.AI_SERVICE_URL) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6000);

        const aiServiceResponse = await fetch(`${env.AI_SERVICE_URL}/api/v1/chat`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message,
            conversationId,
            conversationHistory: request.conversationHistory || [],
            scanId: request.scanId,
            scanContext: scanDataForPrompt,
          }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (aiServiceResponse.ok) {
          const serviceJson: any = await aiServiceResponse.json();
          if (serviceJson?.data?.reply) {
            return {
              reply: serviceJson.data.reply,
              conversationId: serviceJson.data.conversationId || conversationId,
              suggestedActions: serviceJson.data.suggestedActions || ['Explain My Scan', 'Talk to Human Support'],
              sources: serviceJson.data.sources || ['CyberWatch Security Knowledge Base'],
              scanContext,
              escalateToHuman: isEscalationIntent || Boolean(serviceJson.data.escalateToHuman),
              provider: serviceJson.data.provider || 'CyberWatch AI Service',
            };
          }
        }
      } catch (serviceErr: any) {
        // Safe graceful degradation: AI service is isolated, fallback to local engine
        console.warn(
          '[CyberWatch API] Isolated AI microservice unavailable or timed out, executing local grounded fallback:',
          serviceErr?.message || serviceErr
        );
      }
    }

    // 4. Direct External LLM fallback if configured (OpenAI, Gemini, Anthropic)
    const effectiveApiKey = env.AI_API_KEY || env.OPENAI_API_KEY || env.GEMINI_API_KEY || env.ANTHROPIC_API_KEY;
    if (effectiveApiKey) {
      try {
        const externalResult = await this.callExternalLLM(
          message,
          request.conversationHistory || [],
          scanDataForPrompt,
          isEscalationIntent
        );
        return {
          reply: externalResult.reply,
          conversationId,
          suggestedActions: externalResult.suggestedActions,
          sources: externalResult.sources,
          scanContext,
          escalateToHuman: isEscalationIntent || externalResult.escalateToHuman,
          provider: env.AI_PROVIDER || (env.OPENAI_API_KEY ? 'OpenAI' : env.GEMINI_API_KEY ? 'Google Gemini' : 'Anthropic'),
        };
      } catch (err: any) {
        console.warn('[CyberWatch AI] External LLM provider failed, falling back to deterministic security engine:', err?.message || err);
      }
    }

    // 5. Grounded Deterministic CyberWatch Intelligence Engine
    const deterministicResponse = this.generateGroundedResponse(
      message,
      scanDataForPrompt,
      isEscalationIntent,
      userId
    );

    return {
      reply: deterministicResponse.reply,
      conversationId,
      suggestedActions: deterministicResponse.suggestedActions,
      sources: deterministicResponse.sources,
      scanContext,
      escalateToHuman: isEscalationIntent || deterministicResponse.escalateToHuman,
      provider: 'CyberWatch Grounded Intelligence Engine',
    };
  },

  /**
   * Deterministic Grounded Security Knowledge & Scan Diagnostics Reasoner.
   */
  generateGroundedResponse(
    message: string,
    scanData: any,
    isEscalation: boolean,
    _userId?: string
  ): {
    reply: string;
    suggestedActions: string[];
    sources: string[];
    escalateToHuman: boolean;
  } {
    const lower = message.toLowerCase();

    // Case 1: Human Escalation Request
    if (isEscalation) {
      return {
        reply:
          'I understand you would like to speak directly with our human support team. You can either open a real-time **Live Chat** session with our active support desk or submit a **Support Ticket** with attachments and scan context.',
        suggestedActions: ['Start Live Chat', 'Open Support Ticket', 'View My Tickets'],
        sources: ['CyberWatch Support SLA Policy', 'Live Desk Documentation'],
        escalateToHuman: true,
      };
    }

    // Case 2: Specific Scan Context Analysis
    if (scanData) {
      const { target, targetType, riskScore, riskLevel, verdict, findings } = scanData;
      const displayScore = riskScore !== undefined ? riskScore : 'N/A';
      const displayLevel = riskLevel || verdict || 'Evaluated';

      const findingsList = findings && findings.length > 0
        ? findings
            .map(
              (f: any, i: number) =>
                `**${i + 1}. [${f.severity || 'INFO'}] ${f.title || 'Security Finding'}**\n- ${f.description || 'Observed telemetry anomaly.'}\n- *Remediation:* ${f.recommendation || 'Apply standard security hardening.'}`
            )
            .join('\n\n')
        : 'No high or critical findings were recorded for this target.';

      if (lower.includes('score') || lower.includes('why') || lower.includes('risk')) {
        return {
          reply: `### Scan Assessment for \`${target}\`\n\n` +
            `**Target Type:** ${targetType || 'Asset'}\n` +
            `**Overall Risk Score:** **${displayScore}/100 (${displayLevel})**\n\n` +
            `#### How this score was calculated:\n` +
            `CyberWatch combines deterministic telemetry checks and severity weights across headers, TLS status, redirect integrity, and threat intelligence.\n\n` +
            `#### Primary Findings Breakdown:\n\n${findingsList}\n\n` +
            `Would you like step-by-step remediation commands or assistance reporting these findings?`,
          suggestedActions: ['How to fix these findings', 'Export PDF Report', 'Talk to Human Support'],
          sources: [`Scan Telemetry (${target})`, 'CyberWatch Scoring Matrix v2', 'OWASP Top 10 Standards'],
          escalateToHuman: false,
        };
      }

      return {
        reply: `### Contextual Analysis for \`${target}\` (${targetType || 'Asset'})\n\n` +
          `Your scan evaluated with a **Risk Score of ${displayScore}/100 (${displayLevel})** with **${findings?.length || 0} finding(s)**.\n\n` +
          `${findingsList}\n\n` +
          `How can I help you remediate or further investigate these results?`,
        suggestedActions: ['Explain risk score', 'Remediation guide', 'Open ticket for assistance'],
        sources: [`Scan Telemetry (${target})`, 'CyberWatch Engine Documentation'],
        escalateToHuman: false,
      };
    }

    // Case 3: Asking about Scanners
    if (lower.includes('scanner') || lower.includes('url') || lower.includes('website') || lower.includes('api') || lower.includes('file') || lower.includes('extension')) {
      return {
        reply:
          `### CyberWatch Scanning Suite Overview\n\n` +
          `CyberWatch provides 6 dedicated security scanners designed for distinct security perimeters:\n\n` +
          `1. **URL & Phishing Mega Scanner**: Inspects domain age, redirect chains, punycode spoofing, and malicious telemetry.\n` +
          `2. **Website Security Scanner V2**: Analyzes HTTP security headers (HSTS, CSP), cookie security flags, forms, and TLS posture.\n` +
          `3. **API Security Scanner**: Audits REST/GraphQL endpoints for CORS misconfigurations, authorization headers, and data exposure.\n` +
          `4. **File Security Scanner**: Static binary and archive analysis with multi-provider hashes, Shannon entropy, and YARA rules.\n` +
          `5. **Browser Extension Scanner**: Inspects Chrome/Firefox extension manifests and JavaScript AST for high-risk permissions and dynamic code execution.\n` +
          `6. **Threat Intelligence Correlation**: Real-time IP, domain, and file indicator matching against global threat feeds.\n\n` +
          `Select a specific scanner to learn more or launch a scan from the Security Services directory.`,
        suggestedActions: ['Scanner Guide', 'View Security Services', 'Run a URL Scan'],
        sources: ['CyberWatch Scanner Documentation', 'Platform Architecture Guide'],
        escalateToHuman: false,
      };
    }

    // Case 4: Asking about Risk Scoring
    if (lower.includes('score') || lower.includes('rating') || lower.includes('calculation')) {
      return {
        reply:
          `### CyberWatch Risk Scoring Methodology\n\n` +
          `CyberWatch scores target security on a standardized scale from **0 to 100**:\n\n` +
          `- **0 – 19 (SAFE):** Robust security controls; no critical flaws or malicious indicators.\n` +
          `- **20 – 39 (LOW):** Minor hardening opportunities (e.g., missing optional headers like Permissions-Policy).\n` +
          `- **40 – 69 (SUSPICIOUS):** Significant posture weaknesses (e.g., missing HSTS/CSP, permissive CORS, weak TLS ciphers).\n` +
          `- **70 – 89 (HIGH RISK):** Severe vulnerabilities (e.g., unauthenticated endpoints, credential exposure, high-risk extension permissions).\n` +
          `- **90 – 100 (CRITICAL):** Confirmed active threats (malware hashes, active phishing, verified remote code execution).\n\n` +
          `Points are additive based on verified evidence items and normalized to ensure transparent, reproducible verdicts.`,
        suggestedActions: ['View My Scans', 'Open Scanner Guide', 'Security FAQ'],
        sources: ['CyberWatch Risk Scoring Matrix v2', 'CVSS v3.1 Specification'],
        escalateToHuman: false,
      };
    }

    // Case 5: Threat Intelligence & Feeds
    if (lower.includes('threat') || lower.includes('intel') || lower.includes('ioc') || lower.includes('reputation')) {
      return {
        reply:
          `### Threat Intelligence Engine\n\n` +
          `CyberWatch aggregates real-time indicators of compromise (IOCs) from premier security intelligence sources:\n\n` +
          `- **AbuseIPDB:** IPv4 and IPv6 abuse confidence ratings and malicious traffic telemetry.\n` +
          `- **VirusTotal & MalwareBazaar:** Multi-engine binary hash analysis and malware family tracking.\n` +
          `- **AlienVault OTX & URLhaus:** Real-time pulse feeds and malicious URL blacklists.\n` +
          `- **CISA Advisories:** Known exploited vulnerability (KEV) alerts and remediation guidelines.\n\n` +
          `You can explore correlated indicators in the **Threat Intelligence** hub.`,
        suggestedActions: ['Threat Intelligence Hub', 'Threat Indicators', 'Security Advisories'],
        sources: ['CyberWatch Threat Intel Orchestrator', 'Provider Registry'],
        escalateToHuman: false,
      };
    }

    // Case 6: Troubleshooting & Errors
    if (lower.includes('troubleshoot') || lower.includes('error') || lower.includes('failed') || lower.includes('unreachable') || lower.includes('timeout')) {
      return {
        reply:
          `### Scanner Troubleshooting Guide\n\n` +
          `If a scan failed or returned **Unreachable / Timeout**, common causes include:\n\n` +
          `1. **Private/Internal IPs (SSRF Protection):** For security, CyberWatch blocks scans against \`localhost\`, \`127.0.0.1\`, \`10.x.x.x\`, and internal IP ranges.\n` +
          `2. **Firewall / Cloudflare Challenge:** Targets with strict bot protection or geo-blocking may reject automated security audit probes.\n` +
          `3. **TLS Handshake Failure:** Expired certificates or unsupported legacy TLS ciphers (TLS 1.0) can cause connection drops.\n` +
          `4. **Target Down or Invalid Protocol:** Verify that the URL includes a valid public hostname with \`http://\` or \`https://\`.\n\n` +
          `If the target is publicly accessible but still failing, please reach out to our team via Live Chat.`,
        suggestedActions: ['Start Live Chat', 'Open Support Ticket', 'Help & FAQ'],
        sources: ['Troubleshooting Knowledge Base', 'SSRF Guard Policies'],
        escalateToHuman: false,
      };
    }

    // Default Informative Response
    return {
      reply:
        `Hello! I am your **CyberWatch AI Security Assistant**.\n\n` +
        `I can help you analyze security scan results, explain risk scores, guide you through remediation steps, and assist with scanner configurations.\n\n` +
        `**How can I assist you today?**\n` +
        `- Select a recent scan above to get a deep findings breakdown.\n` +
        `- Ask questions about security headers, CORS, file malware analysis, or browser extensions.\n` +
        `- Or connect with a human engineer anytime using the support button below.`,
      suggestedActions: ['Explain My Scan', 'Why Is My Risk Score High?', 'Scanner Troubleshooting', 'Talk to Human Support'],
      sources: ['CyberWatch Knowledge Base', 'Security Documentation'],
      escalateToHuman: false,
    };
  },

  /**
   * Optional External LLM Integration (OpenAI / Gemini / Anthropic) with strict grounding.
   */
  async callExternalLLM(
    userMessage: string,
    history: Array<{ role: 'user' | 'assistant' | 'system'; content: string }>,
    scanContext: any,
    isEscalation: boolean
  ): Promise<{
    reply: string;
    suggestedActions: string[];
    sources: string[];
    escalateToHuman: boolean;
  }> {
    const apiKey = env.AI_API_KEY || env.OPENAI_API_KEY;
    if (apiKey) {
      const systemPrompt =
        `You are the official CyberWatch AI Security Assistant. You assist cybersecurity professionals and developers in understanding CyberWatch scan results, risk scores (0-100), security findings, and threat intelligence.\n` +
        `GROUNDING RULES:\n` +
        `- DO NOT invent, hallucinate, or fabricate risk scores, CVE numbers, or unverified findings.\n` +
        `- Base your technical guidance on the CyberWatch architecture: URL & Phishing Scanner, Website Security Scanner V2, API Scanner, File Scanner, Browser Extension Scanner, and Threat Intelligence feeds (AbuseIPDB, VirusTotal, OTX).\n` +
        `- If the user asks about an unknown scan or something not verified, politely explain what you know and suggest talking to Human Support.\n` +
        (scanContext ? `CURRENT AUTHORIZED SCAN DATA:\n${JSON.stringify(scanContext, null, 2)}\n` : '');

      const messages = [
        { role: 'system', content: systemPrompt },
        ...history.slice(-6).map((m) => ({ role: m.role, content: m.content })),
        { role: 'user', content: userMessage },
      ];

      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: env.AI_MODEL || 'gpt-4o-mini',
          messages,
          temperature: 0.3,
          max_tokens: 800,
        }),
      });

      if (!response.ok) {
        throw new Error(`OpenAI API responded with ${response.status}`);
      }

      const json: any = await response.json();
      const reply = json.choices?.[0]?.message?.content || 'No response generated.';

      return {
        reply,
        suggestedActions: ['Explain My Scan', 'Scanner Guide', 'Talk to Human Support'],
        sources: ['CyberWatch Knowledge Base', 'OpenAI Grounded Model'],
        escalateToHuman: isEscalation,
      };
    }

    throw new Error('No external LLM provider configured.');
  },
};
