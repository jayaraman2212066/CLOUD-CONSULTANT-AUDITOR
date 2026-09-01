# CloudConsultant Auditor — AWS Security Report Generator

Turn Prowler JSON into a boardroom-ready security report in seconds.

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green)
![Vercel](https://img.shields.io/badge/deployed-Vercel-black)

---

## Features

- Supports **Prowler v2, v3, v4, v5 (JSON-OCSF), v6 (AWS ASFF)** and ScoutSuite
- **Elite PDF Report** — executive summary, findings table, compliance badges, remediation roadmap
- **Ultimate PDF Report** — CLI + Terraform code blocks, risk heatmap, 3-phase roadmap, document control
- **MITRE ATT&CK** mapping for every finding
- **Compliance** cross-mapping: CIS, NIST 800-53, PCI-DSS, ISO 27001, SOC 2
- **IaC Viewer** — AWS CLI, Terraform, CloudFormation remediation snippets
- **CSV export** and **Evidence Bundle** (ZIP: PDF + CSV + README)
- **Trend history** — security score tracking across scans
- **Embedded voice agent** — Gemini-powered audit guidance with browser voice input/output
- **Accounts** — optional email/password sign-in with HttpOnly sessions and saved scan summaries
- **Free tier** — 3 lifetime analyses, no signup required
- **License key** activation via Polar.sh

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI + Python 3.12 |
| Database | Supabase PostgreSQL (SQLite for local dev) |
| PDF Generation | ReportLab |
| Payments | Polar.sh |
| Deployment | Vercel (serverless via Mangum) |
| Frontend | Vanilla JS + Chart.js |

---

## Local Development

### 1. Clone the repo

```bash
git clone https://github.com/jayaraman2212066/CLOUD-CONSULTANT-AUDITOR.git
cd CLOUD-CONSULTANT-AUDITOR
```

### 2. Set up environment

```bash
cp backend/.env.example backend/.env
# Edit backend/.env and fill in your credentials
```

### 3. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 4. Run the server

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open [http://localhost:8000](http://localhost:8000)

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Supabase PostgreSQL connection string |
| `POLAR_ACCESS_TOKEN` | Polar.sh API token |
| `POLAR_ORGANIZATION_ID` | Polar.sh organization ID |
| `POLAR_WEBHOOK_SECRET` | Polar.sh webhook signing secret |
| `POLAR_PRODUCT_ID_FREELANCER` | Polar product ID for Freelancer plan |
| `POLAR_PRODUCT_ID_CONSULTANT_PRO` | Polar product ID for Consultant Pro plan |
| `POLAR_PRODUCT_ID_PAY_PER_REPORT` | Polar product ID for Pay Per Report |
| `ALLOWED_ORIGINS` | Comma-separated allowed CORS origins |
| `MAX_JSON_MB` | Max upload size in MB (default: 50) |
| `FREE_TIER_LIMIT` | Free analyses per device (default: 3) |
| `SESSION_SECRET` | Random secret for session signing |
| `GEMINI_API_KEY` | Google AI Studio key for the embedded agent; keep server-side |
| `GEMINI_MODEL` | Gemini model name (default: `gemini-3.6-flash`) |
| `SUPABASE_URL` | Reserved Supabase project URL for future provider integration |
| `SUPABASE_ANON_KEY` | Reserved public Supabase client key for future OAuth integration |

---

## Deployment (Vercel)

1. Push this repo to GitHub
2. Import into [Vercel](https://vercel.com)
3. Add all environment variables from the table above in **Vercel → Settings → Environment Variables**
4. Set `ALLOWED_ORIGINS` to your Vercel deployment URL
5. Deploy

The `vercel.json` and `api/index.py` are pre-configured for serverless deployment.

---

## Pricing

| Plan | Price | Reports |
|------|-------|---------|
| Free | $0 | 3 lifetime |
| Pay Per Report | $5.99 | 1 report |
| Freelancer | $79/mo | 15/month |
| Consultant Pro | $199/mo | 60/month |

---

## License

MIT — see [LICENSE](LICENSE) for details.
