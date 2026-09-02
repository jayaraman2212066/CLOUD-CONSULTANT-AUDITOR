import sys
import os
import traceback
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="Diagnostic")

# Try to add backend to sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_path)

@app.get("/health")
@app.get("/api/health")
async def health_check():
    files_in_parent = []
    files_in_backend = []
    parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    try:
        files_in_parent = os.listdir(parent_dir)
    except Exception as e:
        files_in_parent = [f"err: {e}"]
    try:
        files_in_backend = os.listdir(backend_path)
    except Exception as e:
        files_in_backend = [f"err: {e}"]
    
    import_err = None
    try:
        import main
        has_main = True
    except Exception as e:
        has_main = False
        import_err = traceback.format_exc()

    return {
        "status": "online",
        "parent_dir": parent_dir,
        "files_in_parent": files_in_parent,
        "backend_path": backend_path,
        "files_in_backend": files_in_backend,
        "has_main": has_main,
        "import_err": import_err
    }
