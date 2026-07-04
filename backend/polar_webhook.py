"""
polar_webhook.py — Polar.sh webhook handler.

Polar webhook event types handled:
  order.created / order.paid      → pay_per_report one-time purchase
  subscription.created            → new freelancer / consultant_pro subscription
  subscription.updated            → renewal, tier change, reactivation
  subscription.canceled / revoked → deactivate license
  subscription.active             → reactivate on renewal

Polar webhook payload shape (v2 API):
{
  "type": "order.created",
  "data": {
    "id": "<order_id>",
    "product_id": "<product_id>",
    "customer": {"email": "..."},
    "license_keys": [{"key": "XXXX-XXXX-XXXX-XXXX", ...}]   ← top-level array
  }
}

For subscriptions:
{
  "type": "subscription.created",
  "data": {
    "id": "<subscription_id>",
    "product_id": "<product_id>",
    "status": "active",
    "customer": {"email": "..."},
    "license_keys": [{"key": "XXXX-XXXX-XXXX-XXXX", ...}]
  }
}
"""
import os
import hmac
import hashlib
import json
import logging
from datetime import datetime

from dotenv import load_dotenv
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session

from database import LicenseKey, CreditTransaction, User
from auth import PRODUCT_TIER_MAP, TIER_LIMITS, _current_month, _sha256

load_dotenv()
logger = logging.getLogger("cloud-brief.webhook")

POLAR_WEBHOOK_SECRET = os.getenv("POLAR_WEBHOOK_SECRET", "")


# ── Signature verification ────────────────────────────────────────────────────

def _verify_signature(payload: bytes, sig_header: str) -> None:
    """
    Polar signs webhooks with HMAC-SHA256.
    Header 'webhook-signature' format: 'v1,<hex_digest>' (may contain multiple
    comma-separated signatures for key rotation).
    """
    if not POLAR_WEBHOOK_SECRET:
        raise HTTPException(500, "Webhook secret not configured.")
    expected = hmac.new(
        POLAR_WEBHOOK_SECRET.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256,
    ).hexdigest()
    # Polar sends 'v1,<hex>' — extract all hex parts and compare any
    sigs = [part.split(",", 1)[-1].strip() for part in sig_header.split() if part]
    if not any(hmac.compare_digest(expected, s) for s in sigs):
        raise HTTPException(401, "Invalid webhook signature.")


# ── License key extraction ────────────────────────────────────────────────────

def _extract_license_key(data: dict) -> str:
    """
    Extract the raw license key string from a Polar event data payload.
    Polar can deliver it in several locations depending on API version:
      1. data["license_keys"][0]["key"]          ← v2 preferred
      2. data["benefits"][n]["license_key"]["key"] ← v1 benefits array
      3. data["license_key"]["key"]              ← flat (some order events)
    Returns empty string if not found.
    """
    # v2: top-level license_keys array
    lk_list = data.get("license_keys", [])
    if lk_list and isinstance(lk_list, list):
        key = lk_list[0].get("key", "")
        if key:
            return key

    # v1: benefits array
    for benefit in data.get("benefits", []):
        if benefit.get("type") == "license_keys":
            key = benefit.get("license_key", {}).get("key", "")
            if key:
                return key

    # flat
    flat = data.get("license_key", {})
    if isinstance(flat, dict):
        return flat.get("key", "")

    return ""


# ── Upsert license row ────────────────────────────────────────────────────────

def _upsert_license(
    db: Session,
    order_id: str,
    product_id: str,
    license_key_raw: str,
    email: str = "",
) -> LicenseKey:
    """
    Create or update a LicenseKey row.
    - Uses the raw license key hash as the primary lookup key.
    - Falls back to order_id hash if no license key was delivered yet
      (Polar sometimes sends the key in a separate benefit event).
    - Correctly resets monthly counters for subscription tiers.
    """
    tier  = PRODUCT_TIER_MAP.get(product_id, "pay_per_report")
    limit = TIER_LIMITS[tier]

    # Prefer the real license key; fall back to order_id as identifier
    lookup_raw = license_key_raw if license_key_raw else order_id
    key_hash   = _sha256(lookup_raw)
    prefix     = lookup_raw[:8]

    existing = db.query(LicenseKey).filter_by(key_hash=key_hash).first()
    if existing:
        # Reactivate / update on renewal
        existing.is_active     = True
        existing.tier          = tier
        existing.reports_limit = limit
        existing.polar_product_id = product_id
        # Reset monthly counter on renewal for subscription tiers
        if tier in ("freelancer", "consultant_pro"):
            current_month = _current_month()
            if existing.month_reset != current_month:
                existing.reports_used = 0
                existing.month_reset  = current_month
        db.commit()
        db.refresh(existing)
        logger.info("License updated: tier=%s key_prefix=%s", tier, prefix)
        return existing

    # New license key
    lk = LicenseKey(
        key_hash=key_hash,
        key_prefix=prefix,
        tier=tier,
        polar_order_id=order_id,
        polar_product_id=product_id,
        reports_used=0,
        reports_limit=limit,
        month_reset=_current_month() if tier in ("freelancer", "consultant_pro") else None,
        is_active=True,
    )
    db.add(lk)

    # Record credit transaction if we can link to a user
    if email:
        user = db.query(User).filter_by(email=email).first()
        if user:
            tx = CreditTransaction(
                user_id=user.id,
                amount=limit,
                polar_order_id=order_id,
            )
            db.add(tx)

    db.commit()
    db.refresh(lk)
    logger.info("License created: tier=%s limit=%d key_prefix=%s email=%s",
                tier, limit, prefix, email or "unknown")
    return lk


# ── Event handlers ────────────────────────────────────────────────────────────

def _handle_order(data: dict, db: Session) -> str:
    """Handles order.created and order.paid (same logic)."""
    order_id        = data.get("id", "")
    product_id      = data.get("product_id", "")
    email           = data.get("customer", {}).get("email", "")
    license_key_raw = _extract_license_key(data)

    if not product_id:
        logger.warning("order event missing product_id, skipping")
        return "skipped: no product_id"

    _upsert_license(db, order_id, product_id, license_key_raw, email)
    return f"order processed: {order_id} tier={PRODUCT_TIER_MAP.get(product_id, 'pay_per_report')}"


def _handle_subscription_created(data: dict, db: Session) -> str:
    sub_id          = data.get("id", "")
    product_id      = data.get("product_id", "")
    email           = data.get("customer", {}).get("email", "")
    license_key_raw = _extract_license_key(data)

    if not product_id:
        logger.warning("subscription.created missing product_id, skipping")
        return "skipped: no product_id"

    _upsert_license(db, sub_id, product_id, license_key_raw, email)
    return f"subscription.created: {sub_id} tier={PRODUCT_TIER_MAP.get(product_id, 'unknown')}"


def _handle_subscription_updated(data: dict, db: Session) -> str:
    """
    Handles subscription.updated and subscription.active.
    On monthly renewal Polar fires subscription.updated with status=active —
    this is where we reset the report counter for the new month.
    """
    sub_id     = data.get("id", "")
    product_id = data.get("product_id", "")
    status     = data.get("status", "active")
    email      = data.get("customer", {}).get("email", "")
    license_key_raw = _extract_license_key(data)

    # Try to find by order_id first, then by license key hash
    lk = db.query(LicenseKey).filter_by(polar_order_id=sub_id).first()
    if not lk and license_key_raw:
        lk = db.query(LicenseKey).filter_by(key_hash=_sha256(license_key_raw)).first()

    if lk:
        new_tier  = PRODUCT_TIER_MAP.get(product_id, lk.tier)
        new_limit = TIER_LIMITS.get(new_tier, lk.reports_limit)
        lk.is_active      = (status in ("active", "trialing"))
        lk.tier           = new_tier
        lk.reports_limit  = new_limit
        lk.polar_product_id = product_id or lk.polar_product_id

        # Reset monthly counter on renewal
        if new_tier in ("freelancer", "consultant_pro"):
            current_month = _current_month()
            if lk.month_reset != current_month:
                lk.reports_used = 0
                lk.month_reset  = current_month
                logger.info("Monthly counter reset for sub %s (%s)", sub_id, new_tier)

        db.commit()
        logger.info("Subscription updated: %s status=%s tier=%s", sub_id, status, new_tier)
        return f"subscription.updated: {sub_id} status={status}"

    # Not found — create it (handles edge case where webhook arrives before activation)
    if product_id and status in ("active", "trialing"):
        _upsert_license(db, sub_id, product_id, license_key_raw, email)
        return f"subscription.updated (new): {sub_id}"

    return f"subscription.updated: {sub_id} not found, skipped"


def _handle_subscription_canceled(data: dict, db: Session) -> str:
    sub_id          = data.get("id", "")
    license_key_raw = _extract_license_key(data)

    lk = db.query(LicenseKey).filter_by(polar_order_id=sub_id).first()
    if not lk and license_key_raw:
        lk = db.query(LicenseKey).filter_by(key_hash=_sha256(license_key_raw)).first()

    if lk:
        lk.is_active = False
        db.commit()
        logger.info("License deactivated: sub=%s", sub_id)
        return f"subscription.canceled: {sub_id} deactivated"

    return f"subscription.canceled: {sub_id} not found"


# ── Main dispatcher ───────────────────────────────────────────────────────────

async def handle_polar_webhook(request: Request, db: Session) -> dict:
    payload = await request.body()
    sig     = request.headers.get("webhook-signature", "")

    # Only verify if secret is configured (allows local testing without it)
    if POLAR_WEBHOOK_SECRET:
        _verify_signature(payload, sig)
    else:
        logger.warning("POLAR_WEBHOOK_SECRET not set — skipping signature verification")

    try:
        event = json.loads(payload)
    except Exception:
        raise HTTPException(400, "Invalid JSON payload.")

    event_type = event.get("type", "")
    data       = event.get("data", {})

    logger.info("Polar webhook received: type=%s", event_type)

    handlers = {
        "order.created":           _handle_order,
        "order.paid":              _handle_order,          # Polar fires both
        "subscription.created":    _handle_subscription_created,
        "subscription.updated":    _handle_subscription_updated,
        "subscription.active":     _handle_subscription_updated,  # renewal
        "subscription.canceled":   _handle_subscription_canceled,
        "subscription.revoked":    _handle_subscription_canceled,
    }

    handler = handlers.get(event_type)
    if handler:
        msg = handler(data, db)
        return {"status": "ok", "message": msg}

    logger.info("Polar webhook ignored: type=%s", event_type)
    return {"status": "ignored", "event_type": event_type}
