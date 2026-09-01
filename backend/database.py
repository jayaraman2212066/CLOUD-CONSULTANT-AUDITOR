import os
from datetime import datetime
from dotenv import load_dotenv
import sqlalchemy
from sqlalchemy import (create_engine, Column, Integer, String, Boolean,
                        DateTime, ForeignKey, Text, text as sa_text)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.pool import NullPool

load_dotenv()

Base = declarative_base()

# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    email         = Column(String, unique=True, nullable=False, index=True)
    provider      = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)
    role          = Column(String, default="user", nullable=False) # Role-based authorization
    trial_used    = Column(Boolean, default=False, nullable=False)
    credits       = Column(Integer, default=0, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    transactions  = relationship("CreditTransaction", back_populates="user")
    license_keys  = relationship("LicenseKey", back_populates="user")
    sessions      = relationship("UserSession", back_populates="user")
    account_sessions = relationship("AccountSession", back_populates="user")


class CreditTransaction(Base):
    __tablename__ = "credit_transactions"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    user_id          = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    amount           = Column(Integer, nullable=False)
    stripe_session_id = Column(String)
    polar_order_id   = Column(String)
    created_at       = Column(DateTime, default=datetime.utcnow, nullable=False)
    user             = relationship("User", back_populates="transactions")


class LicenseKey(Base):
    """Stores Polar license keys after webhook activation."""
    __tablename__ = "license_keys"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    key_hash        = Column(String, unique=True, nullable=False, index=True)
    key_prefix      = Column(String, nullable=False)
    tier            = Column(String, nullable=False)
    polar_order_id  = Column(String, index=True)
    polar_product_id = Column(String)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=True)
    reports_used    = Column(Integer, default=0, nullable=False)
    reports_limit   = Column(Integer, nullable=False)
    month_reset     = Column(String, nullable=True)
    is_active       = Column(Boolean, default=True, nullable=False)
    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)
    user            = relationship("User", back_populates="license_keys")
    sessions        = relationship("UserSession", back_populates="license_key")


class UserSession(Base):
    """Short-lived session tokens issued after license key activation."""
    __tablename__ = "user_sessions"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    token_hash     = Column(String, unique=True, nullable=False, index=True)
    license_key_id = Column(Integer, ForeignKey("license_keys.id"), nullable=False)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=True)
    tier           = Column(String, nullable=False)
    expires_at     = Column(DateTime, nullable=False)
    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False)
    user           = relationship("User", back_populates="sessions")
    license_key    = relationship("LicenseKey", back_populates="sessions")


class AccountSession(Base):
    """Short-lived HttpOnly sessions for email/password accounts."""
    __tablename__ = "account_sessions"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    token_hash = Column(String, unique=True, nullable=False, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    user       = relationship("User", back_populates="account_sessions")


class FreeUsage(Base):
    """Tracks free-tier usage by fingerprint (no account required)."""
    __tablename__ = "free_usage"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint  = Column(String, unique=True, nullable=False, index=True)
    used         = Column(Boolean, default=False, nullable=False)
    uses_count   = Column(Integer, default=0, nullable=False, server_default="0")
    created_at   = Column(DateTime, default=datetime.utcnow, nullable=False)


class ReportHistory(Base):
    """Account-scoped scan summaries; raw findings are never stored here."""
    __tablename__ = "report_history"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    user_id         = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    company_name    = Column(String, nullable=False)
    security_score  = Column(Integer, nullable=False)
    grade           = Column(String, nullable=False)
    severity_counts = Column(Text, nullable=False, default="{}")
    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)


# ── Engine selection ──────────────────────────────────────────────────────────

def _sqlite_engine():
    return create_engine(
        "sqlite:///./database.db",
        connect_args={"check_same_thread": False},
        echo=False,
    )


def _candidate_db_urls():
    candidates = []
    for key in [
        "DATABASE_URL",
        "POSTGRES_URL",
        "POSTGRES_PRISMA_URL",
        "POSTGRES_URL_NON_POOLING",
        "SUPABASE_DB_URL",
    ]:
        value = (os.getenv(key) or "").strip()
        if value:
            candidates.append(value)
    # Keep the direct non-pooling URL ahead of pooler URLs when both are present.
    direct = [u for u in candidates if "pooler.supabase.com" not in u and "pgbouncer=true" not in u]
    pooled = [u for u in candidates if u not in direct]
    return direct + pooled


def _normalize_db_url(raw_url: str) -> str:
    url = raw_url.strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if "pooler.supabase.com" in url and "pgbouncer=true" in url:
        non_pooling = os.getenv("POSTGRES_URL_NON_POOLING") or os.getenv("DATABASE_URL") or url
        if "pooler.supabase.com" not in non_pooling and non_pooling.startswith("postgres"):
            url = non_pooling
    if url.startswith("postgresql://") and "?" not in url:
        url = f"{url}?sslmode=require"
    return url


def _build_engine():
    for raw_url in _candidate_db_urls():
        db_url = _normalize_db_url(raw_url)
        if not db_url.startswith("postgres"):
            continue
        try:
            test_engine = create_engine(
                db_url,
                poolclass=NullPool,
                echo=False,
                connect_args={
                    "options": "-c search_path=public",
                    "connect_timeout": 3,
                },
            )
            with test_engine.connect() as conn:
                conn.execute(sa_text("SELECT 1"))
            return test_engine
        except Exception as exc:
            print(f"[database] DB URL rejected ({db_url.split('@')[1][:60] if '@' in db_url else db_url[:60]}): {exc}")
            continue

    print("[database] No valid PostgreSQL URL found; using SQLite fallback.")
    return _sqlite_engine()


engine       = _build_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)
    # Migrate: add uses_count column to free_usage if it doesn't exist
    db_url = os.getenv("DATABASE_URL", "")
    is_postgres = str(engine.url).startswith("postgres")
    try:
        with engine.connect() as conn:
            if is_postgres:
                # PostgreSQL: check information_schema
                result = conn.execute(sa_text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='free_usage' AND column_name='uses_count'"
                ))
                if result.fetchone() is None:
                    conn.execute(sa_text(
                        "ALTER TABLE free_usage ADD COLUMN uses_count INTEGER NOT NULL DEFAULT 0"
                    ))
                    conn.commit()
                result = conn.execute(sa_text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='users' AND column_name='password_hash'"
                ))
                if result.fetchone() is None:
                    conn.execute(sa_text("ALTER TABLE users ADD COLUMN password_hash VARCHAR"))
                    conn.commit()
            else:
                # SQLite: use PRAGMA
                cols = [r[1] for r in conn.execute(sa_text("PRAGMA table_info(free_usage)")).fetchall()]
                if "uses_count" not in cols:
                    conn.execute(sa_text(
                        "ALTER TABLE free_usage ADD COLUMN uses_count INTEGER NOT NULL DEFAULT 0"
                    ))
                    conn.commit()
                user_cols = [r[1] for r in conn.execute(sa_text("PRAGMA table_info(users)")).fetchall()]
                if "password_hash" not in user_cols:
                    conn.execute(sa_text("ALTER TABLE users ADD COLUMN password_hash VARCHAR"))
                    conn.commit()
    except Exception:
        pass  # table doesn't exist yet — create_all handles it


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
