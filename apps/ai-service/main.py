import os
import json
import re
import urllib.request
import urllib.error
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="CyberWatch AI Security Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Data Models ─────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str = Field(..., description="Role: 'user', 'assistant', or 'system'")
    content: str = Field(..., description="Message text content")

class ScanFindingItem(BaseModel):
    title: str
    severity: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    evidence: Optional[Any] = None

class ScanContextData(BaseModel):
    scanId: Optional[str] = None
    target: Optional[str] = None
    targetType: Optional[str] = None
    riskScore: Optional[int] = None
    riskLevel: Optional[str] = None
    verdict: Optional[str] = None
    findingsCount: Optional[int] = None
    findings: Optional[List[ScanFindingItem]] = None
    evidence: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None
    threatIntelligence: Optional[Dict[str, Any]] = None
    domainIntelligence: Optional[Dict[str, Any]] = None
    httpTlsInfo: Optional[Dict[str, Any]] = None
    phishingFindings: Optional[List[Any]] = None
    extensionFindings: Optional[List[Any]] = None
    fileFindings: Optional[List[Any]] = None

class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    conversationId: Optional[str] = None
    scanId: Optional[str] = None
    scanContext: Optional[ScanContextData] = None
    conversationHistory: Optional[List[ChatMessage]] = Field(default_factory=list)

class AIChatResponseData(BaseModel):
    reply: str
    conversationId: Optional[str] = None
    suggestedActions: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    scanContext: Optional[Dict[str, Any]] = None
    escalateToHuman: bool = False
    provider: str

class AIChatResponse(BaseModel):
    success: bool
    message: str
    data: AIChatResponseData

class HealthResponse(BaseModel):
    service: str
    status: str
    version: str

# ─── System Prompt ───────────────────────────────────────────────────────────

CYBERWATCH_SYSTEM_PROMPT = """You are the official CyberWatch AI Security Assistant.
Your purpose is to provide clear, accurate, concise, and evidence-based cybersecurity guidance, analyze CyberWatch scanner results, and explain technical risk findings to developers, security analysts, and students.

CORE IDENTITY & TONE:
- Name: CyberWatch AI Security Assistant
- Persona: Professional, security-focused, evidence-grounded, empathetic, and easy to understand.
- Keep answers structured with clear headings, bullet points, and actionable remediation steps.

STRICT EVIDENCE & GROUNDING RULES:
1. NEVER fabricate or hallucinate CyberWatch scan results, CVE numbers, vulnerability findings, risk scores, or threat intelligence hits.
2. If scan context is provided, ONLY reference the findings, scores, and indicators that actually exist in the scan data.
3. NEVER change or recalculate the CyberWatch risk score. Use the exact score provided (0-100 scale).
4. NEVER override scanner verdicts.
5. NEVER claim a target is 100% secure or invulnerable.
6. NEVER claim that a website is clean or safe merely because threat intelligence feeds returned zero matches; explain that no known malicious indicators were observed in monitored feeds.
7. If scan information or specific data is unavailable or not provided, explicitly state that it is unavailable.
8. Distinguish clearly between observed evidence (e.g., missing HSTS header, expired TLS certificate) and interpretation/risk impact.
9. If the user asks for human support, billing, or emergency incident assistance, provide clear escalation guidance to connect with human operators or open a Support Ticket.
"""

# ─── Deterministic Grounded Engine ───────────────────────────────────────────

def generate_grounded_fallback_response(
    message: str,
    scan_ctx: Optional[ScanContextData],
    history: List[ChatMessage],
    conversation_id: Optional[str]
) -> AIChatResponseData:
    lower = message.lower()
    
    # 1. Human Escalation Intent
    if any(k in lower for k in ["human", "speak to someone", "operator", "talk to agent", "billing", "refund", "ticket", "emergency"]):
        return AIChatResponseData(
            reply=(
                "I understand you would like to connect directly with our human support team. "
                "You can start a real-time conversation with our active **Live Support Desk** or submit a formal **Support Ticket** with full attachments and diagnostic logs."
            ),
            conversationId=conversation_id,
            suggestedActions=["Start Live Chat", "Open Support Ticket", "View My Tickets"],
            sources=["CyberWatch Support SLA Policy", "Live Desk Directory"],
            scanContext=scan_ctx.model_dump(exclude_none=True) if scan_ctx else None,
            escalateToHuman=True,
            provider="CyberWatch Grounded Intelligence Engine",
        )

    # 2. Specific Scan Context Analysis
    if scan_ctx and (scan_ctx.target or scan_ctx.riskScore is not None):
        target = scan_ctx.target or "Target"
        target_type = scan_ctx.targetType or "Asset"
        score = scan_ctx.riskScore if scan_ctx.riskScore is not None else "N/A"
        level = scan_ctx.riskLevel or scan_ctx.verdict or "Evaluated"
        findings = scan_ctx.findings or []

        if any(k in lower for k in ["score", "why", "risk", "high", "finding", "vulnerability"]):
            if findings:
                findings_text = "\n\n".join(
                    f"**{i+1}. [{f.severity}] {f.title}**\n- {f.description or 'Observed during security audit.'}\n- *Remediation:* {f.recommendation or 'Implement recommended hardening.'}"
                    for i, f in enumerate(findings[:6])
                )
            else:
                findings_text = "No severe findings or malicious indicators were recorded in this scan."

            return AIChatResponseData(
                reply=(
                    f"### Scan Assessment for `{target}`\n\n"
                    f"- **Asset Type:** {target_type}\n"
                    f"- **Recorded Risk Score:** **{score}/100 ({level})**\n\n"
                    f"#### How this score was evaluated:\n"
                    f"CyberWatch evaluates risk deterministically based on observed evidence across transport security, headers, cookies, permissions, and threat feeds.\n\n"
                    f"#### Key Findings Recorded:\n\n{findings_text}\n\n"
                    f"Would you like tailored remediation commands or guidance for fixing these items?"
                ),
                conversationId=conversation_id,
                suggestedActions=["How to fix these findings", "Export PDF Report", "Talk to Human Support"],
                sources=[f"Scan Telemetry ({target})", "CyberWatch Risk Matrix v2", "OWASP Security Guidelines"],
                scanContext=scan_ctx.model_dump(exclude_none=True),
                escalateToHuman=False,
                provider="CyberWatch Grounded Intelligence Engine",
            )
        
        return AIChatResponseData(
            reply=(
                f"### Contextual Overview for `{target}` ({target_type})\n\n"
                f"This scan recorded a **Risk Score of {score}/100 ({level})** with **{len(findings)} finding(s)**.\n\n"
                f"Feel free to ask me to break down any specific finding, explain header requirements (e.g. HSTS, CSP), or suggest remediation steps."
            ),
            conversationId=conversation_id,
            suggestedActions=["Explain risk score", "Remediation guide", "Open ticket for assistance"],
            sources=[f"Scan Telemetry ({target})", "CyberWatch Engine Documentation"],
            scanContext=scan_ctx.model_dump(exclude_none=True),
            escalateToHuman=False,
            provider="CyberWatch Grounded Intelligence Engine",
        )

    # 3. Questions about CyberWatch Scanners
    if any(k in lower for k in ["scanner", "url", "phishing", "website", "api", "file", "extension", "how does"]):
        return AIChatResponseData(
            reply=(
                "### CyberWatch Scanning Suite Overview\n\n"
                "CyberWatch provides 6 specialized security scanners:\n\n"
                "1. **URL & Phishing Mega Scanner:** Analyzes domain age, redirect hops, punycode spoofing, and credential harvesting patterns.\n"
                "2. **Website Security Scanner V2:** Evaluates HTTP security headers (HSTS, CSP), cookie security flags, forms, and TLS posture.\n"
                "3. **API Security Scanner:** Audits REST/GraphQL endpoints for CORS misconfigurations, authorization headers, and information leakage.\n"
                "4. **File Security Scanner:** Static binary and archive analysis with multi-provider hashes, Shannon entropy, and YARA signatures.\n"
                "5. **Browser Extension Scanner:** Audits Chrome/Firefox extension manifests and JavaScript AST for high-risk permissions and exfiltration.\n"
                "6. **Threat Intelligence Correlation:** Aggregates real-time reputation indicators from AbuseIPDB, VirusTotal, AlienVault OTX, and URLhaus."
            ),
            conversationId=conversation_id,
            suggestedActions=["Explain My Scan", "Why Is My Risk Score High?", "Scanner Troubleshooting"],
            sources=["CyberWatch Scanner Architecture Documentation", "Platform Specs"],
            scanContext=None,
            escalateToHuman=False,
            provider="CyberWatch Grounded Intelligence Engine",
        )

    # 4. Questions about Risk Scoring
    if any(k in lower for k in ["score", "scoring", "calculate", "cvss", "rating"]):
        return AIChatResponseData(
            reply=(
                "### CyberWatch Risk Scoring Scale (0 to 100)\n\n"
                "CyberWatch uses an evidence-based risk index where higher scores represent higher security exposure:\n\n"
                "- **0 – 19 (SAFE):** Robust security controls and zero confirmed threats.\n"
                "- **20 – 39 (LOW):** Minor hardening opportunities (e.g. missing Permissions-Policy header).\n"
                "- **40 – 69 (SUSPICIOUS):** Significant posture gaps (e.g. missing HSTS/CSP, permissive CORS, weak TLS ciphers).\n"
                "- **70 – 89 (HIGH RISK):** Critical configuration weaknesses or unauthenticated data exposure.\n"
                "- **90 – 100 (CRITICAL):** Confirmed active threats, known malware hashes, or active phishing indicators."
            ),
            conversationId=conversation_id,
            suggestedActions=["Explain My Scan", "Threat Intelligence Help", "Scanner Troubleshooting"],
            sources=["CyberWatch Risk Scoring Matrix v2", "CVSS v3.1 Standards"],
            scanContext=None,
            escalateToHuman=False,
            provider="CyberWatch Grounded Intelligence Engine",
        )

    # 5. Default Friendly Welcome Response
    return AIChatResponseData(
        reply=(
            "Hello! I am your **CyberWatch AI Security Assistant**.\n\n"
            "I can assist you with:\n"
            "- Analyzing and explaining your scan findings and risk scores\n"
            "- Clarifying HTTP security headers (HSTS, CSP, X-Frame-Options)\n"
            "- Threat intelligence indicators and IP/domain reputation\n"
            "- Phishing identification and browser extension security\n"
            "- Step-by-step remediation advice\n\n"
            "How can I assist your security audit today?"
        ),
        conversationId=conversation_id,
        suggestedActions=["Explain My Scan", "Why Is My Risk Score High?", "Threat Intelligence Help", "Talk to Human Support"],
        sources=["CyberWatch Security Knowledge Base", "OWASP Top 10 Standards"],
        scanContext=None,
        escalateToHuman=False,
        provider="CyberWatch Grounded Intelligence Engine",
    )

# ─── External LLM Calling Helper ─────────────────────────────────────────────

def call_external_llm_provider(
    message: str,
    scan_ctx: Optional[ScanContextData],
    history: List[ChatMessage],
    conversation_id: Optional[str]
) -> Optional[AIChatResponseData]:
    api_key = (
        os.getenv("AI_API_KEY") or
        os.getenv("OPENAI_API_KEY") or
        os.getenv("GEMINI_API_KEY") or
        os.getenv("ANTHROPIC_API_KEY")
    )
    if not api_key:
        return None

    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    
    # Format scan context if available
    scan_ctx_prompt = ""
    if scan_ctx:
        scan_ctx_prompt = f"\n\nCURRENT AUTHORIZED CYBERWATCH SCAN CONTEXT (DO NOT FABRICATE BEYOND THIS DATA):\n{json.dumps(scan_ctx.model_dump(exclude_none=True), indent=2)}"

    system_message = CYBERWATCH_SYSTEM_PROMPT + scan_ctx_prompt

    messages = [{"role": "system", "content": system_message}]
    for msg in history[-6:]:
        messages.append({"role": msg.role, "content": msg.content})
    messages.append({"role": "user", "content": message})

    # OpenAI / Compatible endpoint
    if os.getenv("AI_PROVIDER", "").lower() == "gemini" or (not os.getenv("OPENAI_API_KEY") and os.getenv("GEMINI_API_KEY")):
        gemini_key = os.getenv("GEMINI_API_KEY") or api_key
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        
        contents = []
        for m in messages:
            contents.append({
                "role": "model" if m["role"] == "assistant" else "user",
                "parts": [{"text": m["content"]}]
            })
        
        payload = {
            "contents": contents,
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1000}
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            reply = res_data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            if reply:
                return AIChatResponseData(
                    reply=reply,
                    conversationId=conversation_id,
                    suggestedActions=["Explain My Scan", "Remediation Steps", "Talk to Human Support"],
                    sources=["CyberWatch Grounded Knowledge Base", "Google Gemini Security Engine"],
                    scanContext=scan_ctx.model_dump(exclude_none=True) if scan_ctx else None,
                    escalateToHuman="human" in message.lower(),
                    provider="Google Gemini",
                )
    else:
        # Standard OpenAI-compatible format
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1000,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as res:
            res_data = json.loads(res.read().decode("utf-8"))
            reply = res_data.get("choices", [{}])[0].get("message", {}).get("content", "")
            if reply:
                return AIChatResponseData(
                    reply=reply,
                    conversationId=conversation_id,
                    suggestedActions=["Explain My Scan", "Remediation Steps", "Talk to Human Support"],
                    sources=["CyberWatch Grounded Knowledge Base", f"OpenAI ({model})"],
                    scanContext=scan_ctx.model_dump(exclude_none=True) if scan_ctx else None,
                    escalateToHuman="human" in message.lower(),
                    provider=f"OpenAI ({model})",
                )

    return None

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        service="cyberwatch-ai",
        status="healthy",
        version="1.0.0"
    )

@app.post("/api/v1/chat", response_model=AIChatResponse)
@app.post("/chat", response_model=AIChatResponse)
async def chat_endpoint(request: AIChatRequest):
    try:
        # Try external LLM first if configured
        try:
            external_result = call_external_llm_provider(
                message=request.message,
                scan_ctx=request.scanContext,
                history=request.conversationHistory or [],
                conversation_id=request.conversationId,
            )
            if external_result:
                return AIChatResponse(
                    success=True,
                    message="AI response generated successfully.",
                    data=external_result,
                )
        except Exception as llm_err:
            # Safe log & fallback to deterministic engine
            print(f"[CyberWatch AI] External provider error: {llm_err}")

        # Deterministic grounded fallback
        grounded_data = generate_grounded_fallback_response(
            message=request.message,
            scan_ctx=request.scanContext,
            history=request.conversationHistory or [],
            conversation_id=request.conversationId,
        )

        return AIChatResponse(
            success=True,
            message="AI response generated successfully.",
            data=grounded_data,
        )
    except Exception as e:
        # Guarantee failure isolation — never crash
        print(f"[CyberWatch AI Service] Error: {e}")
        return AIChatResponse(
            success=True,
            message="CyberWatch AI response generated with fallback.",
            data=AIChatResponseData(
                reply="CyberWatch AI is temporarily experiencing high demand. Please try again or connect with our human support desk.",
                conversationId=request.conversationId,
                suggestedActions=["Start Live Chat", "Open Support Ticket"],
                sources=["CyberWatch Support SLA"],
                escalateToHuman=True,
                provider="CyberWatch Safe Fallback",
            ),
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
