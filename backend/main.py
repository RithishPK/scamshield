from fastapi import FastAPI, HTTPException, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from groq import Groq
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os
import json
import re
import io
import httpx
import uuid

# ── env + client ────────────────────────────────────────────────────────────
load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# ── app + rate limiter ───────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── request models ────────────────────────────────────────────────────────────
class MessageRequest(BaseModel):
    message: str

class ReportRequest(BaseModel):
    message_preview: str
    scam_type: str | None
    risk_score: int
    verdict: str
    red_flags: str

class ChatRequest(BaseModel):
    session_id: str
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

CHAT_SYSTEM_PROMPT = """You are ScamShield Assistant — an expert on job scams, fraud detection, and employment safety in India.

You ONLY answer questions related to:
- Job scams and fraud detection
- How to verify if a job offer is legitimate
- Specific scam patterns (registration fee, impersonation, WFH scams, etc.)
- What to do if someone has been scammed
- How to report scams in India
- General job search safety tips
- Explaining risk scores or analysis results from ScamShield

If someone asks about ANYTHING else (coding, general knowledge, entertainment, math, etc.), respond with:
"I'm ScamShield Assistant — I can only help with job scam detection and employment fraud questions. Please ask me something related to that topic."

Always be helpful, clear, and provide actionable advice. Use simple language that a non-technical person can understand.
When relevant, mention cybercrime.gov.in and helpline 1930 for reporting scams in India."""

# ── demo fallback cache ───────────────────────────────────────────────────────
DEMO_CACHE = {
    "scam": {
        "risk_score": 94, "verdict": "Likely Scam", "scam_type": "Registration Fee Scam",
        "red_flags": ["Upfront registration fee demanded", "Unrealistic income promise", "No company name or website", "Urgency pressure tactic", "Personal WhatsApp number only"],
        "safe_signals": [], "advice": "Never pay any fee to get a job — legitimate employers do not charge candidates.",
    },
    "suspicious": {
        "risk_score": 52, "verdict": "Suspicious", "scam_type": "Work From Home Scam",
        "red_flags": ["No company name provided", "Vague job description", "Unsolicited contact"],
        "safe_signals": ["No payment mentioned", "Salary is realistic"],
        "advice": "Ask for the company name and official website before sharing any personal details.",
    },
    "safe": {
        "risk_score": 12, "verdict": "Safe", "scam_type": None,
        "red_flags": [],
        "safe_signals": ["Official company email domain used", "Specific office location provided", "No payment requested", "Interview process mentioned"],
        "advice": "This message appears legitimate. Verify by calling the company directly using their official website number.",
    },
}

SCAM_KEYWORDS = ["fee", "register", "registration", "pay", "payment", "deposit", "guaranteed", "ghar baithe", "घर बैठे", "premium", "urgent", "limited seats", "apply now", "call now", "whatsapp now", "no interview", "no experience", "earn daily", "part time earn"]
SAFE_KEYWORDS = ["interview", "office", "hr@", ".com email", "bring resume", "shortlisted", "scheduled", "department", "joining date"]

def fallback_response(message: str) -> dict:
    msg = message.lower()
    scam_hits = sum(1 for k in SCAM_KEYWORDS if k in msg)
    safe_hits = sum(1 for k in SAFE_KEYWORDS if k in msg)
    if scam_hits >= 2: return DEMO_CACHE["scam"]
    elif safe_hits >= 2: return DEMO_CACHE["safe"]
    else: return DEMO_CACHE["suspicious"]

# ── OCR helper ────────────────────────────────────────────────────────────────
def extract_text_from_image_bytes(image_bytes: bytes) -> str:
    try:
        import easyocr
        import numpy as np
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode not in ('RGB', 'L'):
            img = img.convert('RGB')
        img_array = np.array(img)
        reader = easyocr.Reader(['en'], gpu=False)
        results = reader.readtext(img_array)
        text = ' '.join([result[1] for result in results])
        return text.strip()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"OCR failed: {str(e)}")

# ── core analysis ─────────────────────────────────────────────────────────────
async def run_analysis(message: str) -> dict:
    user_content = f"""{FEW_SHOT_EXAMPLES}

Now analyze this message:
Message: "{message}"

Return exactly this JSON structure:
{{
  "risk_score": <integer 0-100>,
  "verdict": "<Safe | Suspicious | Likely Scam | Definite Scam>",
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
                {"role": "user", "content": user_content},
            ],
            temperature=0.1, timeout=10,
        )
        text = response.choices[0].message.content.strip()
        text = re.sub(r"```json|```", "", text).strip()
        return json.loads(text)
    except Exception as e:
        print(f"[FALLBACK TRIGGERED] Reason: {e}")
        return fallback_response(message)

MIN_MESSAGE_LENGTH = 10

# ── endpoint 1: text analysis ─────────────────────────────────────────────────
@app.post("/analyze")
@limiter.limit("10/minute")
async def analyze_message(request: Request, req: MessageRequest):
    message = (req.message or "").strip()
    if not message:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Message cannot be empty.")
    if len(message) < MIN_MESSAGE_LENGTH:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Message is too short. Please provide at least {MIN_MESSAGE_LENGTH} characters.")
    return await run_analysis(message)

# ── endpoint 2: file upload analysis (PDF + DOCX + TXT + Images) ─────────────
@app.post("/analyze-file")
@limiter.limit("5/minute")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    allowed_types = [
        "application/pdf",
        "text/plain",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
        "image/jpeg", "image/jpg", "image/png", "image/webp", "image/bmp", "image/tiff"
    ]
    content_type = file.content_type or ""
    filename = file.filename or ""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''

    # Also detect by file extension as fallback
    image_exts = {'jpg', 'jpeg', 'png', 'webp', 'bmp', 'tiff', 'tif'}
    doc_exts = {'pdf': 'application/pdf', 'txt': 'text/plain', 'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'doc': 'application/msword'}

    if not content_type or content_type == 'application/octet-stream':
        if ext in image_exts:
            content_type = f'image/{ext}'
    elif ext in doc_exts:
        content_type = doc_exts[ext]

    if not any(ct in content_type for ct in allowed_types) and ext not in image_exts and ext not in doc_exts:
        raise HTTPException(status_code=400, detail="Unsupported file type. Upload PDF, DOCX, TXT, or image (JPG/PNG/WEBP).")

    contents = await file.read()
    extracted_text = ""

    # ── PDF ──
    if "pdf" in content_type:
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(contents)) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        extracted_text += page_text + "\n"

            # If PDF has no extractable text, use OCR on page images
            if not extracted_text.strip():
                try:
                    import easyocr
                    import numpy as np
                    reader = easyocr.Reader(['en'], gpu=False)
                    from pdf2image import convert_from_bytes
                    images = convert_from_bytes(contents, dpi=150)
                    for img in images:
                        img_array = np.array(img)
                        results = reader.readtext(img_array)
                        page_text = ' '.join([r[1] for r in results])
                        if page_text:
                            extracted_text += page_text + "\n"
                except Exception as ocr_e:
                    raise HTTPException(status_code=422, detail=f"PDF appears image-based and OCR failed: {str(ocr_e)}")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Could not process PDF: {str(e)}")

    # ── DOCX ──
    elif "wordprocessingml" in content_type or "msword" in content_type:
        try:
            from docx import Document as DocxDocument
            doc = DocxDocument(io.BytesIO(contents))
            extracted_text = "\n".join([para.text for para in doc.paragraphs if para.text.strip()])
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Could not read Word document: {str(e)}")

    # ── Plain text ──
    elif "text/plain" in content_type:
        try:
            extracted_text = contents.decode("utf-8")
        except UnicodeDecodeError:
            extracted_text = contents.decode("latin-1")

    # ── Images (JPG, PNG, WEBP, etc.) ──
    elif any(img_type in content_type for img_type in ["image/jpeg", "image/jpg", "image/png", "image/webp", "image/bmp", "image/tiff"]) or ext in image_exts:
        extracted_text = extract_text_from_image_bytes(contents)
        if not extracted_text:
            raise HTTPException(status_code=422, detail="No text found in image. Make sure the image contains readable text.")

    extracted_text = extracted_text.strip()
    if not extracted_text:
        raise HTTPException(status_code=422, detail="No text could be extracted. The file may be empty or unreadable.")
    if len(extracted_text) < MIN_MESSAGE_LENGTH:
        raise HTTPException(status_code=400, detail="Extracted text is too short to analyze.")
    if len(extracted_text) > 3000:
        extracted_text = extracted_text[:3000] + "..."

    result = await run_analysis(extracted_text)
    result["extracted_preview"] = extracted_text[:300] + ("..." if len(extracted_text) > 300 else "")
    result["source"] = f"Extracted from: {file.filename}"
    return result

# ── endpoint 3: report a scam ─────────────────────────────────────────────────
@app.post("/report-scam")
@limiter.limit("3/minute")
async def report_scam(request: Request, req: ReportRequest):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Database not configured.")
    try:
        async with httpx.AsyncClient() as client_http:
            response = await client_http.post(
                f"{SUPABASE_URL}/rest/v1/scam_reports",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"},
                json={"message_preview": req.message_preview[:200], "scam_type": req.scam_type, "risk_score": req.risk_score, "verdict": req.verdict, "red_flags": req.red_flags}
            )
        if response.status_code in [200, 201]:
            return {"success": True, "message": "Scam reported successfully. Thank you for helping others!"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save report.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# ── endpoint 4: get recent scam reports ───────────────────────────────────────
@app.get("/recent-scams")
@limiter.limit("30/minute")
async def get_recent_scams(request: Request):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Database not configured.")
    try:
        async with httpx.AsyncClient() as client_http:
            response = await client_http.get(
                f"{SUPABASE_URL}/rest/v1/scam_reports",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
                params={"select": "id,message_preview,scam_type,risk_score,verdict,red_flags,reported_at", "order": "reported_at.desc", "limit": "20"}
            )
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

# ── endpoint 5: chat message ──────────────────────────────────────────────────
@app.post("/chat")
@limiter.limit("20/minute")
async def chat(request: Request, req: ChatRequest):
    if not req.session_id or not req.message.strip():
        raise HTTPException(status_code=400, detail="session_id and message are required.")

    # Fetch last 10 messages for context
    history = []
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            async with httpx.AsyncClient() as client_http:
                resp = await client_http.get(
                    f"{SUPABASE_URL}/rest/v1/chat_history",
                    headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
                    params={"select": "role,message,created_at", "session_id": f"eq.{req.session_id}", "order": "created_at.asc", "limit": "10"}
                )
            history = resp.json() if resp.status_code == 200 else []
        except:
            history = []

    # Build messages for LLM
    messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]
    for h in history:
        messages.append({"role": h["role"], "content": h["message"]})
    messages.append({"role": "user", "content": req.message})

    # Call LLM
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.3,
            timeout=15,
            max_tokens=800,
        )
        reply = response.choices[0].message.content.strip()
    except Exception as e:
        reply = "I'm having trouble connecting right now. Please try again in a moment."

    # Save both messages to Supabase
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            async with httpx.AsyncClient() as client_http:
                await client_http.post(
                    f"{SUPABASE_URL}/rest/v1/chat_history",
                    headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"},
                    json={"session_id": req.session_id, "role": "user", "message": req.message}
                )
                await client_http.post(
                    f"{SUPABASE_URL}/rest/v1/chat_history",
                    headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json", "Prefer": "return=minimal"},
                    json={"session_id": req.session_id, "role": "assistant", "message": reply}
                )
        except:
            pass

    return {"reply": reply, "session_id": req.session_id}

# ── endpoint 6: get chat history ──────────────────────────────────────────────
@app.get("/chat-history/{session_id}")
@limiter.limit("30/minute")
async def get_chat_history(request: Request, session_id: str):
    if not SUPABASE_URL or not SUPABASE_KEY:
        return []
    try:
        async with httpx.AsyncClient() as client_http:
            resp = await client_http.get(
                f"{SUPABASE_URL}/rest/v1/chat_history",
                headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
                params={"select": "role,message,created_at", "session_id": f"eq.{session_id}", "order": "created_at.asc", "limit": "50"}
            )
        return resp.json() if resp.status_code == 200 else []
    except:
        return []

# ── health check ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"status": "ScamShield API is running", "version": "3.0"}
