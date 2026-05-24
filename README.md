\# ScamShield — Fake Job Scam Detector (FastAPI + Groq)



ScamShield is a FastAPI backend that analyzes \*\*job scam messages\*\* (especially those circulated on \*\*WhatsApp/Telegram in India\*\*) and returns a structured risk assessment using the \*\*Groq API\*\* (Llama 3.3 70B).



Built for HackArena 2.0 — Bangalore Zonals (trae.ai track) by \*\*Mind Flayer Hunters\*\*, Nitte Meenakshi Institute of Technology.



\## What it does



Send a suspicious message to the API and get back:

\- `risk\_score` (0–100)

\- `verdict`: `Safe` / `Suspicious` / `Likely Scam` / `Definite Scam`

\- `scam\_type`: `Registration Fee Scam`, `Guaranteed Job Scam`, `Work From Home Scam`, `Data Harvesting Scam`, `Impersonation Scam`, `Other`, or `null`

\- `red\_flags`, `safe\_signals`

\- One-line `advice`



The backend includes a \*\*smart fallback\*\* (keyword-based cache) if Groq rate-limits during demos — zero downtime.



\## Project structure



```text

scam-detector/

├─ backend/

│  ├─ main.py        # FastAPI app (POST /analyze, GET /)

│  └─ evaluate.py    # 20-message labeled test set, writes CSV evaluation report

├─ frontend/

│  └─ index.html     # Static UI — animated risk gauge, red flags, safe signals

└─ requirements.txt

```



\## Setup



\### 1) Prerequisites

\- Python 3.10+

\- A free Groq API key from console.groq.com



\### 2) Create \& activate a virtual environment



\*\*Windows\*\*

```powershell

python -m venv venv

venv\\Scripts\\activate

```



\*\*macOS/Linux\*\*

```bash

python -m venv venv

source venv/bin/activate

```



\### 3) Install dependencies



```bash

pip install -r requirements.txt

```



\## Configuration



Create `backend/.env`:



```env

GROQ\_API\_KEY=your\_groq\_api\_key\_here

```



\*\*Never commit `.env` to GitHub.\*\* It is already in `.gitignore`.



\## Run the backend



```bash

cd backend

uvicorn main:app --reload

```



\- API: http://127.0.0.1:8000

\- Swagger docs: http://127.0.0.1:8000/docs



\## API usage



\### Analyze a message



```bash

curl -X POST http://127.0.0.1:8000/analyze \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d "{\\"message\\":\\"Urgent hiring! Work from home. Earn Rs 800/hour. Registration fee Rs 500 only. WhatsApp now.\\"}"

```



Example response:



```json

{

&#x20; "risk\_score": 94,

&#x20; "verdict": "Likely Scam",

&#x20; "scam\_type": "Registration Fee Scam",

&#x20; "red\_flags": \["Upfront registration fee demanded", "Unrealistic income promise"],

&#x20; "safe\_signals": \[],

&#x20; "advice": "Never pay any fee to get a job — legitimate employers do not charge candidates."

}

```



\## Run the frontend



1\. Start the backend (see above)

2\. Open `frontend/index.html` in your browser

3\. Paste any WhatsApp or Telegram job message and click \*\*Analyze\*\*



\## Evaluation



With the backend running:



```bash

cd backend

python evaluate.py

```



Runs 20 labeled test messages through the API and prints accuracy, precision, recall, and F1 score. Saves a full CSV report.



\*\*Results on 20-message test set:\*\* 100% accuracy, 100% scam recall, 100% F1.



\## Tech stack



\- \*\*Backend:\*\* FastAPI, Python, Groq API (Llama 3.3 70B)

\- \*\*Frontend:\*\* HTML, CSS, JavaScript (single file, no framework)

\- \*\*Developed with:\*\* trae.ai (SOLO)

\- \*\*Evaluation:\*\* Responsible AI principles — transparency, calibration, explainability



\## License



MIT License — free to use and modify.

