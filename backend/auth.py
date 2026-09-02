"""
auth.py — License key activation, session management, report-count enforcement.

Tiers and report limits:
  free            → 3 lifetime analyses (matches frontend cb_free_uses default)
  freelancer      → 15 reports / calendar-month
  consultant_pro  → 60 reports / calendar-month
  pay_per_report  → 1 report per purchase (one-time)
"""
import os
import hashlib
import secrets
import base64
import hmac
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from database import LicenseKey, UserSession, FreeUsage, User, AccountSession

load_dotenv()
logger = logging.getLogger("cloud-brief.auth")

POLAR_ACCESS_TOKEN = os.getenv("POLAR_ACCESS_TOKEN", "")
POLAR_API_BASE     = "https://api.polar.sh"

TIER_LIMITS: dict[str, int] = {
    "free":           3,   # matches frontend cb_free_uses default of 3
    "freelancer":     15,
    "consultant_pro": 60,
    "pay_per_report": 1,
}

PRODUCT_TIER_MAP: dict[str, str] = {
    k: v for k, v in {
        os.getenv("POLAR_PRODUCT_ID_FREELANCER",     "beaa1c6d-456b-49b7-93ee-6f0b5fe3a3ff"): "freelancer",
        os.getenv("POLAR_PRODUCT_ID_CONSULTANT_PRO", "16766b30-ab0d-42ef-85d1-534f709d021b"): "consultant_pro",
        os.getenv("POLAR_PRODUCT_ID_PAY_PER_REPORT", "932bdbd1-decf-49ba-869c-f9aa57610d7c"): "pay_per_report",
    }.items() if k  # exclude empty-string keys when env vars are unset
}

SESSION_TTL_HOURS = 72  # session token valid for 3 days
ACCOUNT_SESSION_TTL_HOURS = 168


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + base64.urlsafe_b64encode(salt + digest).decode("ascii")


def verify_password(password: str, encoded: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(encoded.split("$", 1)[1].encode("ascii"))
        salt, expected = raw[:16], raw[16:]
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, IndexError):
        return False


def create_account_session(user: User, db: Session) -> str:
    token = secrets.token_urlsafe(32)
    db.add(AccountSession(token_hash=_sha256(token), user_id=user.id,
                           expires_at=datetime.utcnow() + timedelta(hours=ACCOUNT_SESSION_TTL_HOURS)))
    db.commit()
    return token


def get_account_session(token: str, db: Session) -> Optional[AccountSession]:
    if not token:
        return None
    session = db.query(AccountSession).filter_by(token_hash=_sha256(token)).first()
    if not session or session.expires_at < datetime.utcnow():
        return None
    return session


def account_token(request: Request) -> str:
    return request.cookies.get("account_token", "") or request.headers.get("X-Account-Token", "")


def _current_month() -> str:
    return datetime.utcnow().strftime("%Y-%m")


def _fingerprint(request: Request) -> str:
    """Lightweight fingerprint for free-tier enforcement: hash of IP + User-Agent."""
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    return _sha256(f"{ip}:{ua}")[:32]


# ── Free tier ─────────────────────────────────────────────────────────────────

FREE_TIER_LIMIT = int(os.getenv("FREE_TIER_LIMIT", "3"))  # matches frontend default


def check_free_tier(request: Request, db: Session) -> None:
    """Raises 403 if this fingerprint has exhausted all free uses."""
    fp  = _fingerprint(request)
    row = db.query(FreeUsage).filter_by(fingerprint=fp).first()
    if row and row.uses_count >= FREE_TIER_LIMIT:
        raise HTTPException(
            status_code=403,
            detail="free_used:Your free analyses have been used. Activate a license key to continue.",
        )


def consume_free_tier(request: Request, db: Session) -> None:
    """Increments the free-tier use counter for this fingerprint."""
    fp  = _fingerprint(request)
    row = db.query(FreeUsage).filter_by(fingerprint=fp).first()
    if not row:
        row = FreeUsage(fingerprint=fp, used=True, uses_count=1)
        db.add(row)
    else:
        row.uses_count = (row.uses_count or 0) + 1
        row.used = row.uses_count >= FREE_TIER_LIMIT
    db.commit()


# ── Polar API ─────────────────────────────────────────────────────────────────

async def _polar_validate_license(key: str) -> dict:
    """
    Validate a Polar license key via the Polar v2 API.

    Polar v2 /v1/license-keys/validate response shape:
    {
      "id": "<license_key_id>",
      "key": "XXXX-XXXX-XXXX-XXXX",
      "status": "granted",
      "benefit": {
        "id": "...",
        "product_id": "<product_id>",
        ...
      },
      "order": {"id": "<order_id>", ...},
      "subscription": {"id": "<sub_id>", "product_id": "...", ...}
    }

    Returns normalised dict: {product_id, order_id}
    """
    if not POLAR_ACCESS_TOKEN:
        raise HTTPException(500, "Polar API token not configured.")

    headers = {"Authorization": f"Bearer {POLAR_ACCESS_TOKEN}"}

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        resp = await client.post(
            f"{POLAR_API_BASE}/v1/license-keys/validate",
            json={"key": key},
            headers=headers,
        )

    if resp.status_code == 403:
        body = resp.json()
        if "insufficient_scope" in body.get("error", ""):
            raise HTTPException(
                500,
                "Polar token missing 'license_keys:read' scope. "
                "Regenerate POLAR_ACCESS_TOKEN in the Polar dashboard with that scope.",
            )
        raise HTTPException(403, f"Polar API access denied: {resp.text[:200]}")

    if resp.status_code == 404:
        raise HTTPException(404, "License key not found or invalid.")

    if resp.status_code not in (200, 201):
        raise HTTPException(400, f"Polar validation failed ({resp.status_code}): {resp.text[:200]}")

    data = resp.json()

    # Extract product_id — check benefit, subscription, then top-level
    product_id = (
        (data.get("benefit") or {}).get("product_id")
        or (data.get("subscription") or {}).get("product_id")
        or data.get("product_id")
        or ""
    )

    # Extract order/subscription id for our records
    order_id = (
        (data.get("order") or {}).get("id")
        or (data.get("subscription") or {}).get("id")
        or data.get("order_id")
        or data.get("subscription_id")
        or data.get("id", "")
    )

    logger.info("Polar license validated: product_id=%s order_id=%s", product_id, order_id)
    return {"product_id": product_id, "order_id": order_id}


# ── License key activation ────────────────────────────────────────────────────

async def activate_license_key(raw_key: str, db: Session) -> dict:
    """
    1. Check if key already exists in our DB (re-activation path).
    2. If not, validate against Polar API and create the LicenseKey row.
    3. Issue a short-lived session token.

    Returns {"session_token", "tier", "reports_remaining", "expires_in_hours"}
    """
    raw_key = raw_key.strip()
    if not raw_key:
        raise HTTPException(400, "License key is required.")

    key_hash = _sha256(raw_key)
    existing = db.query(LicenseKey).filter_by(key_hash=key_hash).first()

    if not existing:
        # First activation — validate with Polar
        polar_data = await _polar_validate_license(raw_key)

        product_id = polar_data.get("product_id", "")
        tier       = PRODUCT_TIER_MAP.get(product_id, "pay_per_report")
        limit      = TIER_LIMITS[tier]

        existing = LicenseKey(
            key_hash=key_hash,
            key_prefix=raw_key[:8],
            tier=tier,
            polar_order_id=polar_data.get("order_id", ""),
            polar_product_id=product_id or "unknown",
            reports_used=0,
            reports_limit=limit,
            month_reset=_current_month() if tier in ("freelancer", "consultant_pro") else None,
            is_active=True,
        )
        db.add(existing)
        db.commit()
        db.refresh(existing)
        logger.info("License key activated: tier=%s limit=%d prefix=%s", tier, limit, raw_key[:8])

    else:
        # Re-activation: reset monthly counter if needed
        if existing.tier in ("freelancer", "consultant_pro"):
            current_month = _current_month()
            if existing.month_reset != current_month:
                existing.reports_used = 0
                existing.month_reset  = current_month
                db.commit()
        logger.info("License key re-activated: tier=%s prefix=%s", existing.tier, raw_key[:8])

    if not existing.is_active:
        raise HTTPException(403, "This license key has been deactivated.")

    # Issue session token
    token      = secrets.token_urlsafe(32)
    token_hash = _sha256(token)
    session    = UserSession(
        token_hash=token_hash,
        license_key_id=existing.id,
        tier=existing.tier,
        expires_at=datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS),
    )
    db.add(session)
    db.commit()

    remaining = _reports_remaining(existing, db)
    return {
        "session_token":    token,
        "tier":             existing.tier,
        "reports_remaining": remaining,
        "expires_in_hours": SESSION_TTL_HOURS,
    }


# ── Session validation ────────────────────────────────────────────────────────

def get_session(token: str, db: Session) -> Optional[UserSession]:
    if not token:
        return None
    token_hash = _sha256(token)
    session    = db.query(UserSession).filter_by(token_hash=token_hash).first()
    if not session:
        return None
    if session.expires_at < datetime.utcnow():
        return None
    return session


# ── Report counter ────────────────────────────────────────────────────────────

def _reports_remaining(lk: LicenseKey, db: Session = None) -> int:
    """
    Return how many reports remain for this license key.
    For subscription tiers, resets the counter at the start of each calendar month.
    Pass db to persist the reset immediately.
    """
    if lk.tier in ("freelancer", "consultant_pro"):
        current_month = _current_month()
        if lk.month_reset != current_month:
            lk.reports_used = 0
            lk.month_reset  = current_month
            if db:
                db.commit()
    return max(0, lk.reports_limit - lk.reports_used)


# ── Report-count enforcement ──────────────────────────────────────────────────

def enforce_report_limit(session: UserSession, db: Session) -> LicenseKey:
    """
    Verify the session's license key has reports remaining and decrement the counter.
    Raises 403 if the limit is reached.
    Returns the LicenseKey row (decremented but not yet committed — caller must commit).
    """
    lk = db.query(LicenseKey).filter_by(id=session.license_key_id).first()
    if not lk or not lk.is_active:
        raise HTTPException(403, "License key is no longer active.")

    remaining = _reports_remaining(lk, db)
    if remaining <= 0:
        tier_label = lk.tier.replace("_", " ").title()
        raise HTTPException(
            403,
            f"limit_reached:{tier_label} report limit reached. "
            f"Upgrade your plan or purchase a pay-per-report credit.",
        )

    lk.reports_used += 1
    return lk


# ── Auth context helper ───────────────────────────────────────────────────────

def get_auth_context(request: Request, db: Session) -> dict:
    """
    Returns {"tier", "session", "is_free"}.
    Does not raise — callers handle free-tier checks separately.
    """
    token   = (
        request.headers.get("X-Session-Token")
        or request.cookies.get("session_token")
        or ""
    )
    session = get_session(token, db) if token else None
    if session:
        return {"tier": session.tier, "session": session, "is_free": False}
    return {"tier": "free", "session": None, "is_free": True}


# ── RBAC Authorization ────────────────────────────────────────────────────────

def require_admin(request: Request, db: Session) -> User:
    """
    Enforce Role-Based Access Control (RBAC). 
    Requires the current user to have the 'admin' role.
    """
    session = get_account_session(account_token(request), db)
    if not session or not session.user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    
    if session.user.role != "admin":
        logger.warning(f"Unauthorized admin access attempt by user: {session.user.email}")
        raise HTTPException(status_code=403, detail="Forbidden: Admin access required.")
        
    return session.user
