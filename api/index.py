"""
Vercel serverless entry point.
Vercel's @vercel/python runtime uses a WSGI bridge internally —
we expose the raw FastAPI ASGI app; Vercel handles the ASGI<->WSGI
translation itself via its runtime shim.
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

import traceback

try:
    from main import app  # noqa: F401  — Vercel looks for `app`
except Exception as e:
    err_tb = traceback.format_exc()
    print(f"[VERCEL STARTUP ERROR] {err_tb}")
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    app = FastAPI(title="Error Fallback")

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def fallback_route(path: str):
        return JSONResponse(
            status_code=500,
            content={
                "error": "FastAPI failed to initialize on Vercel",
                "detail": str(e),
                "traceback": err_tb
            }
        )
