# 🛡️ ScamShield — AI Job Scam Detector

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Groq](https://img.shields.io/badge/Groq-Llama%203.3%2070B-F55036?style=for-the-badge)
![trae.ai](https://img.shields.io/badge/Built%20with-trae.ai-00C853?style=for-the-badge)

**AI-powered detector for fake job messages on WhatsApp & Telegram in India**

*HackArena 2.0 — Bangalore Zonals (trae.ai Track)*
*Team: Mind Flayer Hunters — Nitte Meenakshi Institute of Technology*

</div>

---

## 🚨 The Problem

Every day, millions of Indians receive fake job messages on WhatsApp and Telegram — promising guaranteed income, work-from-home opportunities, and instant hiring. Victims pay ₹500–₹5,000 in "registration fees" before realizing it's a scam. No tool existed specifically for these short, informal messages — until now.

---

## ✅ What ScamShield Does

Paste any suspicious job message and get back an instant AI-powered risk assessment:

| Field | Description |
|-------|-------------|
| `risk_score` | 0–100 risk score |
| `verdict` | `Safe` / `Suspicious` / `Likely Scam` / `Definite Scam` |
| `scam_type` | `Registration Fee Scam`, `Guaranteed Job Scam`, `Work From Home Scam`, `Data Harvesting Scam`, `Impersonation Scam` |
| `red_flags` | Specific suspicious phrases/patterns detected |
| `safe_signals` | Legitimate signals found in the message |
| `advice` | One actionable sentence for the user |

> 💡 **Smart Fallback:** If Groq rate-limits during a live demo, a keyword-based cache returns the correct response automatically — zero downtime.

---

## 🗂️ Project Structure

```
scam-detector/
├── backend/
│   ├── main.py          # FastAPI app — POST /analyze, GET /
│   └── evaluate.py      # 20-message labeled test set + CSV evaluation report
├── frontend/
│   └── index.html       # Single-file UI — animated risk gauge, red flags, safe signals
└── requirements.txt
```

---

## ⚙️ Setup

### Prerequisites
- Python 3.10+
- Free Groq API key from [console.groq.com](https://console.groq.com)

### 1. Clone the repo

```bash
git clone https://github.com/RithishPK/scamshield.git
cd scamshield
```

### 2. Create & activate virtual environment

**Windows**
```powershell
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux**
```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

Create `backend/.env`:

```env
GROQ_API_KEY=your_groq_api_key_here
```

> ⚠️ Never commit `.env` to GitHub. It is already listed in `.gitignore`.

---

## 🚀 Run the Backend

```bash
cd backend
uvicorn main:app --reload
```

- **API:** http://127.0.0.1:8000
- **Swagger docs:** http://127.0.0.1:8000/docs

---

## 🌐 Run the Frontend

1. Start the backend (above)
2. Open `frontend/index.html` in your browser
3. Paste any WhatsApp or Telegram job message → click **Analyze**

---

## 📡 API Reference

### `POST /analyze`

**Request**
```json
{ "message": "Urgent hiring! Work from home. Earn Rs 800/hour. Registration fee Rs 500 only." }
```

**Response**
```json
{
  "risk_score": 94,
  "verdict": "Likely Scam",
  "scam_type": "Registration Fee Scam",
  "red_flags": ["Upfront registration fee demanded", "Unrealistic income promise", "No company name"],
  "safe_signals": [],
  "advice": "Never pay any fee to get a job — legitimate employers do not charge candidates."
}
```

---

## 🧪 Evaluation

Run the responsible AI evaluation script against a 20-message labeled test set:

```bash
cd backend
python evaluate.py
```

### Results

| Metric | Score |
|--------|-------|
| Overall Accuracy | **100%** (20/20) |
| Scam Precision | **100%** |
| Scam Recall | **100%** |
| F1 Score | **100%** |

> ⚠️ Honest caveat: Test set was curated. Real-world accuracy on unseen data would be lower.

**Responsible AI principles applied:**
- ✅ **Transparency** — all predictions logged with scores and reasoning
- ✅ **Calibration** — accuracy measured against labeled ground truth
- ✅ **Explainability** — red flags verified against known scam pattern categories

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, Python 3.10+ |
| LLM Inference | Groq API (Llama 3.3 70B) |
| Frontend | HTML, CSS, JavaScript |
| AI IDE | trae.ai SOLO |
| Evaluation | Custom responsible AI evaluation script |

---

## 📄 License

MIT License — free to use and modify.
