"""
Vercel serverless entry point.
Imports the FastAPI app from backend/main.py, wraps it with Mangum
so Vercel's @vercel/python (ASGI) runtime can serve it.
"""
import sys
import os

# Make backend/ importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Load .env from backend/ only when running locally (no-op on Vercel)
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(__file__), '..', 'backend', '.env')
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except Exception:
    pass

from main import app as _fastapi_app  # noqa: F401
from mangum import Mangum

# Vercel invokes `handler` as the ASGI entry point
handler = Mangum(_fastapi_app, lifespan="off")  # noqa: F401

# Also expose `app` for any tooling that looks for it
app = handler  # noqa: F401
