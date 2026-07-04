"""
Integration test runner — validates all endpoints before server start.
Run: python run_tests.py
"""
import sys, io, json, os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
import main

client = TestClient(main.app, raise_server_exceptions=False)

PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  [PASS] {label}")
        PASS += 1
    else:
        print(f"  [FAIL] {label}  {detail}")
        FAIL += 1

print("\n=== CloudBrief Integration Tests ===\n")

# ── Static routes ─────────────────────────────────────────────────────────────
print("[Static Routes]")
for path in ["/", "/styles.css", "/dashboard.js", "/pricing.html", "/terms.html", "/privacy.html"]:
    r = client.get(path)
    check(f"GET {path}", r.status_code == 200, f"got {r.status_code}")

# ── Health / Readiness ────────────────────────────────────────────────────────
print("\n[Health & Readiness]")
r = client.get("/health")
check("GET /health -> 200", r.status_code == 200)
check("/health returns version", r.json().get("version") == "3.0.0")

r = client.get("/ready")
check("GET /ready -> 200 or 503", r.status_code in (200, 503))
check("/ready has db field", "db" in r.json())

# ── Auth endpoints ────────────────────────────────────────────────────────────
print("\n[Auth Endpoints]")
r = client.get("/license/status")
check("GET /license/status -> 200", r.status_code == 200)
data = r.json()
check("/license/status has tier", "tier" in data)
check("/license/status unauthenticated = free", data.get("tier") == "free")
check("/license/status authenticated=False", data.get("authenticated") == False)

r = client.post("/license/activate", json={})
check("POST /license/activate missing key -> 400", r.status_code == 400)

r = client.post("/license/activate", content=b"not-json", headers={"Content-Type": "application/json"})
check("POST /license/activate bad JSON -> 400", r.status_code == 400)

# ── Free endpoints ────────────────────────────────────────────────────────────
print("\n[Free Endpoints]")
r = client.get("/iac-snippet?check_id=s3_bucket_public_access&fmt=cli")
check("GET /iac-snippet cli -> 200", r.status_code == 200)
check("/iac-snippet has snippet key", "snippet" in r.json())

r = client.get("/iac-snippet?check_id=test&fmt=invalid")
check("GET /iac-snippet bad fmt -> 400", r.status_code == 400)

r = client.get("/trend-history?company_name=TestCo")
check("GET /trend-history -> 200", r.status_code == 200)
check("/trend-history has history key", "history" in r.json())

# ── Preview findings with real test file ─────────────────────────────────────
print("\n[Preview Findings]")
test_json_path = "../test_prowler.json"
if os.path.exists(test_json_path):
    with open(test_json_path, "rb") as f:
        r = client.post("/preview-findings",
                        files={"file": ("test.json", f, "application/json")},
                        data={"company_name": "Test Corp"})
    check("POST /preview-findings -> 200", r.status_code == 200, f"got {r.status_code}: {r.text[:200]}")
    if r.status_code == 200:
        d = r.json()
        check("/preview-findings has score", "score" in d)
        check("/preview-findings has findings", "findings" in d)
        check("/preview-findings has severity", "severity" in d)
        check("/preview-findings has costs", "costs" in d)
else:
    print("  [SKIP] test_prowler.json not found — skipping preview test")

# ── Download script ───────────────────────────────────────────────────────────
print("\n[Script Builder]")
r = client.post("/download-script?fmt=sh",
                json={"findings": [{"check_id": "s3_bucket_public_access", "title": "S3 Public", "severity": "high"}]},
                headers={"Content-Type": "application/json"})
check("POST /download-script sh -> 200", r.status_code == 200, f"got {r.status_code}")

r = client.post("/download-script?fmt=ps1",
                json={"findings": [{"check_id": "iam_root_mfa", "title": "Root MFA", "severity": "critical"}]},
                headers={"Content-Type": "application/json"})
check("POST /download-script ps1 -> 200", r.status_code == 200)

# ── Webhook (signature check) ─────────────────────────────────────────────────
print("\n[Polar Webhook]")
r = client.post("/webhooks/polar", content=b'{"type":"order.created","data":{}}',
                headers={"Content-Type": "application/json", "webhook-signature": "badsig"})
check("POST /webhooks/polar bad sig -> 401", r.status_code == 401)

# ── Auth-gated endpoints (no token = free tier check) ─────────────────────────
print("\n[Auth-Gated Endpoints — no token]")
# These should either work (first free use) or return 403 free_used
# We just check they don't 500
if os.path.exists(test_json_path):
    with open(test_json_path, "rb") as f:
        r = client.post("/generate-report",
                        files={"file": ("test.json", f, "application/json")},
                        data={"company_name": "Test Corp"})
    check("POST /generate-report no-token -> 200 or 403", r.status_code in (200, 403), f"got {r.status_code}")

    with open(test_json_path, "rb") as f:
        r = client.post("/export-csv",
                        files={"file": ("test.json", f, "application/json")})
    check("POST /export-csv -> 200", r.status_code == 200, f"got {r.status_code}")

    with open(test_json_path, "rb") as f:
        r = client.post("/export-json",
                        files={"file": ("test.json", f, "application/json")})
    check("POST /export-json -> 200", r.status_code == 200, f"got {r.status_code}")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'='*40}")
print(f"  Results: {PASS} passed, {FAIL} failed")
print(f"{'='*40}\n")
sys.exit(0 if FAIL == 0 else 1)
