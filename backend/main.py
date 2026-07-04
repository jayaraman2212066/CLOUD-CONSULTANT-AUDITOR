import io
import json
import os
import csv
import zipfile
import time
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from dotenv import load_dotenv
load_dotenv()

from fastapi import (FastAPI, UploadFile, File, Form, HTTPException,
                     Request, Depends, status)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (StreamingResponse, FileResponse,
                               HTMLResponse, JSONResponse)
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from services.parser_enterprise import (
    parse_findings, group_by_severity, group_by_service,
    calculate_risk_score, deduplicate_findings,
)
from services.pdf_generator_elite import generate_pdf_elite
from services.pdf_generator_ultimate import generate_pdf_ultimate
from services.cost_estimator import estimate_costs
from services.iac_templates import get_all_formats
from services.script_builder import build_script
from database import init_db, SessionLocal
from auth import (
    check_free_tier, consume_free_tier,
    activate_license_key, get_session,
    enforce_report_limit, _reports_remaining,
)
from polar_webhook import handle_polar_webhook
import sqlalchemy

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("cloud-brief")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AWS Security Report Generator", version="3.0.0",
              docs_url=None, redoc_url=None)

@app.on_event("startup")
def startup():
    try:
        init_db()
        logger.info("Database initialised.")
    except Exception as e:
        logger.error("Database init failed (non-fatal): %s", e)

BASE_DIR     = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
HISTORY_DIR  = Path(__file__).resolve().parent / "scan_history"
try:
    HISTORY_DIR.mkdir(exist_ok=True)
except OSError:
    pass  # read-only filesystem (Vercel serverless)

# ── CORS (env-driven) ─────────────────────────────────────────────────────────
_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Session-Token"],
    allow_credentials=False,
)

# ── Exception handlers ────────────────────────────────────────────────────────
@app.exception_handler(StarletteHTTPException)
async def http_exc_handler(request: Request, exc: StarletteHTTPException):
    logger.warning("HTTP %s %s - %s", exc.status_code, request.url.path, exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.exception_handler(RequestValidationError)
async def validation_exc_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422,
                        content={"detail": "Invalid request data", "errors": str(exc)})

@app.exception_handler(Exception)
async def general_exc_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(status_code=500,
                        content={"detail": f"Internal server error: {str(exc)}"})

# ── Rate limiter (20 req/min per IP) ─────────────────────────────────────────
_rate_store: dict = defaultdict(list)
_rate_store_last_clean = 0.0

def rate_limit(request: Request):
    global _rate_store_last_clean
    ip  = request.client.host if request.client else "unknown"
    now = time.time()
    # Evict stale IPs every 5 minutes to prevent unbounded memory growth
    if now - _rate_store_last_clean > 300:
        stale = [k for k, v in _rate_store.items() if not any(now - t < 60 for t in v)]
        for k in stale:
            del _rate_store[k]
        _rate_store_last_clean = now
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < 60]
    if len(_rate_store[ip]) >= 20:
        raise HTTPException(429, "Rate limit exceeded. Try again in 1 minute.")
    _rate_store[ip].append(now)

# ── Validators ────────────────────────────────────────────────────────────────
_MAX_JSON_MB   = int(os.getenv("MAX_JSON_MB", "50"))
_MAX_LOGO_MB   = 2
_ALLOWED_COLOR = set("0123456789abcdefABCDEF#")

def _validate_color(c: str) -> str:
    c = c.strip()
    if not c.startswith("#") or len(c) != 7 or not all(x in _ALLOWED_COLOR for x in c):
        return "#1e3a5f"
    return c

def _validate_company(name: str) -> str:
    name = name.strip()[:80]
    return "".join(ch for ch in name if ch.isalnum() or ch in " .,&-_()") or "AWS Account"

# ── History helpers ───────────────────────────────────────────────────────────
def _history_key(company: str) -> str:
    return hashlib.md5(company.lower().encode()).hexdigest()[:12]

def _save_snapshot(company: str, risk: dict, severity: dict):
    path = HISTORY_DIR / f"{_history_key(company)}.json"
    history = []
    if path.exists():
        try:
            history = json.loads(path.read_text())
        except Exception:
            history = []
    history.append({
        "date": datetime.now().isoformat(),
        "score": risk.get("score", 0),
        "grade": risk.get("grade", "F"),
        "grade_label": risk.get("grade_label", risk.get("grade", "F")),
        "total": risk.get("total", 0),
        "severity": severity,
    })
    try:
        path.write_text(json.dumps(history[-12:]))
    except OSError:
        pass  # read-only filesystem (Vercel serverless)

def _load_history(company: str) -> list:
    path = HISTORY_DIR / f"{_history_key(company)}.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []

# ── Shared upload parser ──────────────────────────────────────────────────────
async def _parse_upload(file: UploadFile) -> tuple:
    if not file.filename or not file.filename.lower().endswith(".json"):
        raise HTTPException(400, "Only .json files are accepted.")
    content = await file.read()
    if len(content) > _MAX_JSON_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {_MAX_JSON_MB} MB limit.")
    try:
        raw = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {e}")
    if not isinstance(raw, (list, dict)):
        raise HTTPException(422, "JSON must be an array or object.")
    try:
        findings = parse_findings(raw)
    except Exception as e:
        raise HTTPException(500, f"Error parsing findings: {e}")
    if not findings:
        raise HTTPException(422, "No FAIL security findings found in this file.")
    grouped  = deduplicate_findings(findings)
    severity = group_by_severity(findings)
    by_svc   = group_by_service(findings)
    risk     = calculate_risk_score(findings)
    return raw, findings, grouped, severity, by_svc, risk

# ── Auth helper ───────────────────────────────────────────────────────────────
def _get_token(request: Request) -> str:
    return (request.headers.get("X-Session-Token", "")
            or request.cookies.get("session_token", ""))

# =============================================================================
# STATIC ROUTES
# =============================================================================

@app.get("/", response_class=HTMLResponse)
def read_root():
    for name in ("dashboard.html", "index.html"):
        p = FRONTEND_DIR / name
        if p.exists():
            return FileResponse(p, headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            })
    return HTMLResponse("<h1>Frontend not found</h1>", 404)

@app.get("/dashboard.html", response_class=HTMLResponse)
def serve_dashboard():
    p = FRONTEND_DIR / "dashboard.html"
    return FileResponse(p, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
    }) if p.exists() else HTMLResponse("<h1>Not found</h1>", 404)

@app.get("/styles.css")
def serve_css():
    p = FRONTEND_DIR / "styles.css"
    return FileResponse(p, media_type="text/css", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }) if p.exists() else HTMLResponse("", 404)

@app.get("/logo.png")
def serve_logo():
    p = BASE_DIR / "outputs" / "J-AI-FINAL_CROP.png"
    return FileResponse(p, media_type="image/png") if p.exists() else HTMLResponse("", 404)

@app.get("/logo-full.png")
def serve_logo_full():
    p = BASE_DIR / "outputs" / "J-AI-FINAL.png"
    return FileResponse(p, media_type="image/png") if p.exists() else HTMLResponse("", 404)

@app.get("/favicon.ico")
def serve_favicon():
    p = BASE_DIR / "outputs" / "J-AI-FINAL_CROP.ico"
    return FileResponse(p, media_type="image/x-icon") if p.exists() else HTMLResponse("", 404)

@app.get("/dashboard.js")
def serve_js():
    p = FRONTEND_DIR / "dashboard.js"
    return FileResponse(p, media_type="application/javascript", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }) if p.exists() else HTMLResponse("", 404)

@app.get("/pricing.html", response_class=HTMLResponse)
def serve_pricing():
    p = FRONTEND_DIR / "pricing.html"
    return FileResponse(p) if p.exists() else HTMLResponse("<h1>Not found</h1>", 404)

@app.get("/terms.html", response_class=HTMLResponse)
def serve_terms():
    p = FRONTEND_DIR / "terms.html"
    return FileResponse(p) if p.exists() else HTMLResponse("<h1>Not found</h1>", 404)

@app.get("/privacy.html", response_class=HTMLResponse)
def serve_privacy():
    p = FRONTEND_DIR / "privacy.html"
    return FileResponse(p) if p.exists() else HTMLResponse("<h1>Not found</h1>", 404)

# =============================================================================
# HEALTH & READINESS
# =============================================================================

@app.get("/health")
def health():
    return {"status": "ok", "version": "3.0.0"}

@app.get("/ready")
def ready():
    try:
        db = SessionLocal()
        db.execute(sqlalchemy.text("SELECT 1"))
        db.close()
        return {"status": "ready", "db": True, "version": "3.0.0"}
    except Exception as e:
        logger.error("DB readiness check failed: %s", e)
        return JSONResponse(status_code=503, content={"status": "not_ready", "db": False})

# =============================================================================
# AUTH ENDPOINTS
# =============================================================================

@app.post("/license/activate")
async def license_activate(request: Request):
    """Validate a Polar license key and issue a session token."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required.")
    raw_key = str(body.get("license_key", "")).strip()
    if not raw_key:
        raise HTTPException(400, "license_key is required.")
    db = SessionLocal()
    try:
        result = await activate_license_key(raw_key, db)
    finally:
        db.close()
    logger.info("License activated: tier=%s", result["tier"])
    return JSONResponse(result)

@app.get("/license/status")
def license_status(request: Request):
    """Return current session tier and reports remaining."""
    token = _get_token(request)
    if not token:
        return JSONResponse({"tier": "free", "authenticated": False, "reports_remaining": None})
    db = SessionLocal()
    try:
        session = get_session(token, db)
        if not session:
            return JSONResponse({"tier": "free", "authenticated": False, "reports_remaining": None})
        from database import LicenseKey
        lk = db.query(LicenseKey).filter_by(id=session.license_key_id).first()
        remaining = _reports_remaining(lk, db) if lk else 0
        return JSONResponse({
            "tier": session.tier,
            "authenticated": True,
            "reports_remaining": remaining,
            "expires_at": session.expires_at.isoformat(),
        })
    finally:
        db.close()

# =============================================================================
# CHECKOUT SESSION (creates Polar hosted checkout URL)
# =============================================================================

@app.post("/checkout/create")
async def checkout_create(request: Request, _=Depends(rate_limit)):
    """Create a Polar checkout session and return the hosted URL."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON body required.")

    product_id  = str(body.get("product_id", "")).strip()
    success_url = str(body.get("success_url", "")).strip()
    if not success_url:
        # Build from request origin or fall back to relative path
        origin = request.headers.get("origin", "")
        success_url = f"{origin}/?activated=1" if origin else "/?activated=1"

    if not product_id:
        raise HTTPException(400, "product_id is required.")

    polar_token = os.getenv("POLAR_ACCESS_TOKEN", "")
    if not polar_token:
        raise HTTPException(500, "Polar API token not configured.")

    import httpx as _httpx
    async with _httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        resp = await client.post(
            "https://api.polar.sh/v1/checkouts",
            headers={"Authorization": f"Bearer {polar_token}"},
            json={"product_id": product_id, "success_url": success_url},
        )

    if resp.status_code == 403:
        data = resp.json()
        if "insufficient_scope" in data.get("error", ""):
            raise HTTPException(
                500,
                "Polar token missing 'checkouts:write' scope. "
                "Regenerate POLAR_ACCESS_TOKEN with that scope in the Polar dashboard."
            )
    if resp.status_code not in (200, 201):
        raise HTTPException(502, f"Polar checkout failed: {resp.text[:200]}")

    data = resp.json()
    url  = data.get("url") or data.get("checkout_url") or ""
    if not url:
        raise HTTPException(502, "Polar returned no checkout URL.")

    logger.info("Checkout session created for product %s", product_id)
    return JSONResponse({"url": url})


# =============================================================================
# POLAR WEBHOOK
# =============================================================================

@app.post("/webhooks/polar")
async def polar_webhook(request: Request):
    """Receive Polar.sh order/subscription events."""
    db = SessionLocal()
    try:
        result = await handle_polar_webhook(request, db)
        logger.info("Polar webhook processed: %s", result)
        return JSONResponse(result)
    finally:
        db.close()

# =============================================================================
# 1. PREVIEW FINDINGS  (free — no auth required)
# =============================================================================

@app.post("/preview-findings")
async def preview_findings(
    request: Request,
    file: UploadFile = File(...),
    company_name: str = Form(default="AWS Account"),
    _=Depends(rate_limit),
):
    company_name = _validate_company(company_name)
    _, findings, grouped, severity, by_svc, risk = await _parse_upload(file)
    costs   = estimate_costs(grouped)
    history = _load_history(company_name)

    trend = None
    if history:
        last  = history[-1]
        trend = {
            "prev_score":    last["score"],
            "prev_date":     last["date"][:10],
            "delta":         round(risk["score"] - last["score"], 1),
            "prev_critical": last["severity"].get("critical", 0),
            "curr_critical": severity.get("critical", 0),
        }

    return JSONResponse({
        "total":         risk["total"],
        "score":         risk["score"],
        "grade":         risk["grade"],
        "grade_label":   risk.get("grade_label", risk["grade"]),
        "severity":      severity,
        "by_service":    dict(list(by_svc.items())[:10]),
        "grouped_count": len(grouped),
        "findings": [
            {
                "check_id":           f["check_id"],
                "title":              f["title"],
                "severity":           f["severity"],
                "service":            f["service"],
                "region":             f["region"],
                "account":            f["account"],
                "priority":           f["priority"],
                "affected_count":     f.get("affected_count", 1),
                "affected_resources": f.get("affected_resources", [])[:50],
                "mitre_attack":       f.get("mitre_attack", ""),
                "compliance":         f.get("compliance", {}),
                "technical_risk":     f.get("technical_risk", ""),
                "remediation":        f.get("remediation", []),
            }
            for f in grouped
        ],
        "costs": costs,
        "trend": trend,
        "time_to_fix": {
            "quick_wins":      costs["quick_wins"],
            "arch_risks":      costs["arch_risks"],
            "quick_win_count": costs["quick_win_count"],
            "arch_risk_count": costs["arch_risk_count"],
        },
    })

# =============================================================================
# 2. GENERATE PDF REPORT  (auth-gated)
# =============================================================================

@app.post("/generate-report")
async def generate_report(
    request: Request,
    file: UploadFile = File(...),
    company_name:    str = Form(default="AWS Account"),
    primary_color:   str = Form(default="#1e3a5f"),
    theme:           str = Form(default="corporate"),
    logo: UploadFile = File(default=None),
    exceptions_json: str = Form(default="[]"),
    _=Depends(rate_limit),
):
    company_name  = _validate_company(company_name)
    primary_color = _validate_color(primary_color)
    theme         = theme if theme in ("corporate", "dark", "highcontrast") else "corporate"

    token = _get_token(request)
    db    = SessionLocal()
    try:
        session = get_session(token, db) if token else None
        if session:
            enforce_report_limit(session, db)
            db.commit()
        else:
            check_free_tier(request, db)

        try:
            exc_list = json.loads(exceptions_json)
            if not isinstance(exc_list, list):
                exc_list = []
            exc_list = [str(e)[:100] for e in exc_list[:50]]
        except Exception:
            exc_list = []

        _, findings, grouped, severity, by_svc, risk = await _parse_upload(file)
        main_f = [f for f in grouped if f["check_id"] not in exc_list]
        exc_f  = [f for f in grouped if f["check_id"] in exc_list]

        logo_bytes = None
        if logo and logo.filename:
            lb = await logo.read()
            if len(lb) <= _MAX_LOGO_MB * 1024 * 1024:
                logo_bytes = lb

        costs   = estimate_costs(main_f)
        history = _load_history(company_name)
        _save_snapshot(company_name, risk, severity)

        trend = None
        if history:
            last  = history[-1]
            trend = {
                "prev_score":    last["score"],
                "prev_date":     last["date"][:10],
                "delta":         round(risk["score"] - last["score"], 1),
                "prev_critical": last["severity"].get("critical", 0),
                "curr_critical": severity.get("critical", 0),
            }

        pdf_bytes = generate_pdf_elite(
            company_name=company_name, findings=main_f,
            severity=severity, by_service=by_svc, risk=risk,
            primary_color=primary_color, logo_bytes=logo_bytes,
            costs=costs, trend=trend, exceptions=exc_f, theme=theme,
        )

        if not session:
            consume_free_tier(request, db)
        db.commit()
    finally:
        db.close()

    safe = "".join(c if c.isalnum() else "_" for c in company_name.lower())
    logger.info("PDF report generated: %s", company_name)
    return StreamingResponse(
        io.BytesIO(pdf_bytes), media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security_report_{safe}.pdf"},
    )

# =============================================================================
# 3. GENERATE ULTIMATE REPORT  (auth-gated)
# =============================================================================

@app.post("/generate-ultimate-report")
async def generate_ultimate_report(
    request: Request,
    file: UploadFile = File(...),
    company_name:  str = Form(default="AWS Account"),
    primary_color: str = Form(default="#0A1628"),
    logo: UploadFile = File(default=None),
    _=Depends(rate_limit),
):
    company_name  = _validate_company(company_name)
    primary_color = _validate_color(primary_color)

    token = _get_token(request)
    db    = SessionLocal()
    try:
        session = get_session(token, db) if token else None
        if session:
            enforce_report_limit(session, db)
            db.commit()
        else:
            check_free_tier(request, db)

        _, findings, grouped, severity, by_svc, risk = await _parse_upload(file)

        logo_bytes = None
        if logo and logo.filename:
            lb = await logo.read()
            if len(lb) <= _MAX_LOGO_MB * 1024 * 1024:
                logo_bytes = lb

        account_id = grouped[0].get("account", "123456789012") if grouped else "123456789012"
        _save_snapshot(company_name, risk, severity)

        pdf_bytes = generate_pdf_ultimate(
            company_name=company_name, findings=grouped,
            severity=severity, by_service=by_svc, risk=risk,
            primary_color=primary_color, logo_bytes=logo_bytes,
            account_id=account_id, date_str=datetime.now().strftime("%B %d, %Y"),
        )

        if not session:
            consume_free_tier(request, db)
        db.commit()
    finally:
        db.close()

    safe = "".join(c if c.isalnum() else "_" for c in company_name.lower())
    logger.info("Ultimate report generated: %s", company_name)
    return StreamingResponse(
        io.BytesIO(pdf_bytes), media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ultimate_report_{safe}.pdf"},
    )

# =============================================================================
# 4. IAC SNIPPET  (free)
# =============================================================================

@app.get("/iac-snippet")
def iac_snippet(check_id: str, fmt: str = "cli", _=Depends(rate_limit)):
    if fmt not in {"cli", "terraform", "cloudformation"}:
        raise HTTPException(400, "fmt must be cli, terraform, or cloudformation")
    check_id = check_id.strip()[:120]
    return JSONResponse({"check_id": check_id, "fmt": fmt,
                         "snippet": get_all_formats(check_id)[fmt]})

# =============================================================================
# 5. DOWNLOAD REMEDIATION SCRIPT  (free)
# =============================================================================

@app.post("/download-script")
async def download_script(request: Request, fmt: str = "sh", _=Depends(rate_limit)):
    if fmt not in ("sh", "ps1"):
        raise HTTPException(400, "fmt must be sh or ps1")
    body = await request.json()
    raw_f = body.get("findings", [])
    if not isinstance(raw_f, list) or len(raw_f) > 200:
        raise HTTPException(400, "findings must be a list of up to 200 items")
    safe_f = [
        {"check_id": str(f.get("check_id", ""))[:120],
         "title":    str(f.get("title", ""))[:200],
         "severity": str(f.get("severity", "medium"))[:20]}
        for f in raw_f if isinstance(f, dict)
    ]
    script = build_script(safe_f, fmt)
    media  = "application/x-sh" if fmt == "sh" else "application/x-powershell"
    return StreamingResponse(
        io.BytesIO(script.encode()), media_type=media,
        headers={"Content-Disposition": f"attachment; filename=remediation_script.{fmt}"},
    )

# =============================================================================
# 6. EXPORT CSV  (free)
# =============================================================================

@app.post("/export-csv")
async def export_csv(file: UploadFile = File(...), _=Depends(rate_limit)):
    _, findings, grouped, *_ = await _parse_upload(file)
    buf    = io.StringIO(newline="")
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, escapechar="\\")
    writer.writerow(["#", "Check ID", "Title", "Severity", "Service", "Region",
                     "Account", "Affected Count", "Priority", "MITRE ATT&CK",
                     "Compliance", "Technical Risk", "Business Impact"])
    for i, f in enumerate(grouped, 1):
        comp = "; ".join(f"{k}: {v}" for k, v in (f.get("compliance") or {}).items())
        writer.writerow([
            i, f.get("check_id", "N/A"), f.get("title", "N/A"),
            f.get("severity", "medium").upper(), f.get("service", "N/A"),
            f.get("region", "N/A"), f.get("account", "N/A"),
            f.get("affected_count", 1),
            (f.get("priority", "N/A") or "N/A").replace("\n", " "),
            f.get("mitre_attack", "N/A"), comp or "N/A",
            (f.get("technical_risk", "") or "").replace("\n", " ")[:200],
            (f.get("business_risk",  "") or "").replace("\n", " ")[:200],
        ])
    buf.seek(0)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )

# =============================================================================
# 7. EXPORT EVIDENCE BUNDLE  (auth-gated)
# =============================================================================

@app.post("/export-bundle")
async def export_bundle(
    request: Request,
    file: UploadFile = File(...),
    company_name:  str = Form(default="AWS Account"),
    primary_color: str = Form(default="#1e3a5f"),
    logo: UploadFile = File(default=None),
    _=Depends(rate_limit),
):
    company_name  = _validate_company(company_name)
    primary_color = _validate_color(primary_color)

    token = _get_token(request)
    db    = SessionLocal()
    try:
        session = get_session(token, db) if token else None
        if session:
            enforce_report_limit(session, db)
            db.commit()
        else:
            check_free_tier(request, db)

        _, findings, grouped, severity, by_svc, risk = await _parse_upload(file)
        costs = estimate_costs(grouped)

        logo_bytes = None
        if logo and logo.filename:
            lb = await logo.read()
            if len(lb) <= _MAX_LOGO_MB * 1024 * 1024:
                logo_bytes = lb

        pdf_bytes = generate_pdf_elite(
            company_name=company_name, findings=grouped,
            severity=severity, by_service=by_svc, risk=risk,
            primary_color=primary_color, logo_bytes=logo_bytes,
            costs=costs, trend=None, exceptions=[], theme="corporate",
        )

        buf    = io.StringIO(newline="")
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL, escapechar="\\")
        writer.writerow(["#", "Check ID", "Title", "Severity", "Service",
                         "Region", "Account", "Affected Count", "Priority",
                         "Technical Risk", "Business Impact"])
        for i, f in enumerate(grouped, 1):
            writer.writerow([
                i, f.get("check_id", "N/A"), f.get("title", "N/A"),
                f.get("severity", "medium").upper(), f.get("service", "N/A"),
                f.get("region", "N/A"), f.get("account", "N/A"),
                f.get("affected_count", 1),
                (f.get("priority", "N/A") or "N/A").replace("\n", " "),
                (f.get("technical_risk", "") or "").replace("\n", " ")[:200],
                (f.get("business_risk",  "") or "").replace("\n", " ")[:200],
            ])

        safe    = "".join(c if c.isalnum() else "_" for c in company_name.lower())
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"security_report_{safe}.pdf", pdf_bytes)
            zf.writestr("findings.csv", buf.getvalue())
            zf.writestr("README.txt",
                f"AWS Security Evidence Bundle\n{'='*60}\n\n"
                f"Company:        {company_name}\n"
                f"Generated:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"Score:          {risk['score']}/100  Grade: {risk['grade']}\n"
                f"Total Findings: {risk['total']}\n\n"
                f"Critical: {severity.get('critical',0)}  "
                f"High: {severity.get('high',0)}  "
                f"Medium: {severity.get('medium',0)}  "
                f"Low: {severity.get('low',0)}\n\n"
                f"CONFIDENTIAL - Restricted to authorised personnel only.\n"
            )
        zip_buf.seek(0)

        if not session:
            consume_free_tier(request, db)
        db.commit()
    finally:
        db.close()

    return StreamingResponse(
        zip_buf, media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=evidence_bundle_{safe}.zip"},
    )

# =============================================================================
# 8. TREND HISTORY  (free)
# =============================================================================

@app.get("/trend-history")
def trend_history(company_name: str, _=Depends(rate_limit)):
    return JSONResponse({"history": _load_history(_validate_company(company_name))})

# =============================================================================
# 9. EXPORT ENRICHED JSON  (free — BI / SIEM integration)
# =============================================================================

@app.post("/export-json")
async def export_json(file: UploadFile = File(...), _=Depends(rate_limit)):
    """Fully enriched findings as JSON for BI/SIEM tools."""
    _, findings, grouped, severity, by_svc, risk = await _parse_upload(file)
    return JSONResponse({
        "meta": {
            "score":     risk["score"],
            "grade":     risk["grade"],
            "total":     risk["total"],
            "severity":  severity,
            "generated": datetime.now().isoformat(),
        },
        "findings": grouped,
    })
