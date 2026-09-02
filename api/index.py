import sys
import os

# Make backend/ importable
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_path)

# Load .env when available
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(backend_path, '.env')
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except Exception:
    pass

from main import app  # noqa: F401

