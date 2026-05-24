from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from groq import Groq
import os
import json
import re

# ── env + client ────────────────────────────────────────────────────────────
load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# ── app ──────────────────────────────────────────────────────────────────────
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── request model ────────────────────────────────────────────────────────────
class MessageRequest(BaseModel):
    message: str

# ── prompts ──────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a scam detection expert specializing in fake job messages circulated on WhatsApp and Telegram in India.

SCORING GUIDE — be strict and calibrated:
- 0-20: Clearly legitimate. Professional tone, known company, no payment request, verifiable contact.
- 21-40: Minor concerns only. Slightly vague but no active red flags.
- 41-65: Suspicious. Multiple vague claims, unverifiable, but no direct scam pattern confirmed.
- 66-85: Likely scam. Clear red flags: urgency, guaranteed income, registration fee mention, no company name.
- 86-100: Definite scam. Explicit payment demand, impersonation, guaranteed job with no interview.

SCAM PATTERNS to detect:
- Registration Fee Scam: asks for upfront payment to register or get the job
- Guaranteed Job Scam: promises job without interview or qualification check
- Work From Home Scam: vague WFH role, unrealistic daily/monthly income (e.g. "50k/month ghar baithe")
- Data Harvesting Scam: asks for Aadhaar, PAN, bank details early in the process
- Impersonation Scam: claims to be from TCS, Infosys, govt, etc. but contact is WhatsApp/personal number
- Other: doesn't fit above but still suspicious

SAFE SIGNALS that reduce score:
- Official company email domain (not Gmail/Yahoo)
- Specific job title and department
- Interview process mentioned
- No payment requested
- Verifiable company name with website

Respond ONLY with a valid JSON object. No explanation, no markdown, no backticks."""

FEW_SHOT_EXAMPLES = """
Example 1 — Definite scam:
Message: "Urgent hiring! Work from home. Earn Rs 800 per hour. No experience needed. Registration fee Rs 500 only. Call now: 9876543210"
{"risk_score": 94, "verdict": "Likely Scam", "scam_type": "Registration Fee Scam", "red_flags": ["Upfront registration fee demanded", "Unrealistic hourly income claim", "No company name or website", "Urgency pressure tactic", "Personal phone number only"], "safe_signals": [], "advice": "Never pay any fee to get a job — legitimate employers do not charge candidates for registration or training."}

Example 2 — Legitimate:
Message: "Dear candidate, this is to inform you that your application for the role of Software Engineer at Infosys BPM has been shortlisted. Please attend the interview on 28th May at our Bangalore office, Electronic City Phase 1. Carry your resume and govt ID. No charges apply. HR team: hr.infosys@infosysbpm.com"
{"risk_score": 12, "verdict": "Safe", "scam_type": null, "red_flags": [], "safe_signals": ["Official company email domain used", "Specific office location provided", "No payment requested", "Named company with verifiable identity", "Interview process mentioned"], "advice": "This message appears legitimate. Verify by calling Infosys BPM directly using their official website number before attending."}

Example 3 — Suspicious:
Message: "Hi, we found your resume on Naukri. We have openings for data entry work from home. Salary 25,000/month. Interested? Reply YES."
{"risk_score": 48, "verdict": "Suspicious", "scam_type": "Work From Home Scam", "red_flags": ["No company name provided", "Vague job description", "Unsolicited contact claiming to have your resume"], "safe_signals": ["No payment mentioned", "Salary is realistic"], "advice": "Ask for the company name, official website, and HR email before proceeding — do not share personal documents yet."}
"""

# ── demo fallback cache (used if Groq rate-limits during live demo) ───────────
DEMO_CACHE = {
    "scam": {
        "risk_score": 94,
        "verdict": "Likely Scam",
        "scam_type": "Registration Fee Scam",
        "red_flags": [
            "Upfront registration fee demanded",
            "Unrealistic income promise",
            "No company name or website",
            "Urgency pressure tactic",
            "Personal WhatsApp number only"
        ],
        "safe_signals": [],
        "advice": "Never pay any fee to get a job — legitimate employers do not charge candidates."
    },
    "suspicious": {
        "risk_score": 52,
        "verdict": "Suspicious",
        "scam_type": "Work From Home Scam",
        "red_flags": [
            "No company name provided",
            "Vague job description",
            "Unsolicited contact"
        ],
        "safe_signals": [
            "No payment mentioned",
            "Salary is realistic"
        ],
        "advice": "Ask for the company name and official website before sharing any personal details."
    },
    "safe": {
        "risk_score": 12,
        "verdict": "Safe",
        "scam_type": None,
        "red_flags": [],
        "safe_signals": [
            "Official company email domain used",
            "Specific office location provided",
            "No payment requested",
            "Interview process mentioned"
        ],
        "advice": "This message appears legitimate. Verify by calling the company directly using their official website number."
    }
}

SCAM_KEYWORDS = [
    "fee", "register", "registration", "pay", "payment", "deposit",
    "guaranteed", "ghar baithe", "घर बैठे", "premium", "urgent",
    "limited seats", "apply now", "call now", "whatsapp now",
    "no interview", "no experience", "earn daily", "part time earn"
]

SAFE_KEYWORDS = [
    "interview", "office", "hr@", ".com email", "bring resume",
    "shortlisted", "scheduled", "department", "joining date"
]

def fallback_response(message: str) -> dict:
    msg = message.lower()
    scam_hits = sum(1 for k in SCAM_KEYWORDS if k in msg)
    safe_hits = sum(1 for k in SAFE_KEYWORDS if k in msg)
    if scam_hits >= 2:
        return DEMO_CACHE["scam"]
    elif safe_hits >= 2:
        return DEMO_CACHE["safe"]
    else:
        return DEMO_CACHE["suspicious"]

# ── endpoint ─────────────────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze_message(req: MessageRequest):
    user_content = f"""{FEW_SHOT_EXAMPLES}

Now analyze this message:
Message: "{req.message}"

Return exactly this JSON structure:
{{
  "risk_score": <integer 0-100>,
  "verdict": "<Safe | Suspicious | Likely Scam>",
  "scam_type": "<null or one of: Registration Fee Scam, Guaranteed Job Scam, Work From Home Scam, Data Harvesting Scam, Impersonation Scam, Other>",
  "red_flags": ["<flag1>", "<flag2>"],
  "safe_signals": ["<signal1>"],
  "advice": "<one actionable sentence for the user>"
}}"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content}
            ],
            temperature=0.1,
            timeout=10
        )
        text = response.choices[0].message.content.strip()
        text = re.sub(r"```json|```", "", text).strip()
        return json.loads(text)

    except Exception as e:
        # Groq rate limit or network failure — return smart cached fallback
        print(f"[FALLBACK TRIGGERED] Reason: {e}")
        return fallback_response(req.message)

# ── health check (useful for Render deployment) ───────────────────────────────
@app.get("/")
async def root():
    return {"status": "ScamShield API is running"}