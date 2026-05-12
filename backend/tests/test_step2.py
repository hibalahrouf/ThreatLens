"""
Step 2 E2E Tests — scan_mode routing via upload endpoint.
Run inside the masvs-api container.
"""
import sys
import json
import httpx

BASE = "http://localhost:8000"

# ─── Get auth token ───
print("=== Getting auth token ===")
client = httpx.Client(base_url=BASE, timeout=15.0)

# Try login first
r = client.post("/api/auth/login", json={
    "email": "test@step2.com",
    "password": "testpassword123",
})
if r.status_code != 200:
    # Register
    r = client.post("/api/auth/register", json={
        "email": "test@step2.com",
        "password": "testpassword123",
        "full_name": "Step2 Tester",
    })
    if r.status_code not in (200, 201):
        print(f"FAIL: Could not register: {r.status_code} {r.text}")
        sys.exit(1)

token = r.json()["access_token"]
client.headers["Authorization"] = f"Bearer {token}"
print(f"Token obtained: {token[:20]}...")

# Create a tiny dummy APK (just needs valid extension)
dummy_apk = b"PK\x03\x04" + b"\x00" * 100  # minimal ZIP header


def upload(scan_mode_param=None, label=""):
    """Upload with optional scan_mode, return (status_code, json_or_text)."""
    files = {"file": ("test.apk", dummy_apk, "application/octet-stream")}
    data = {"project_name": "step2-test"}
    if scan_mode_param is not None:
        data["scan_mode"] = scan_mode_param
    r = client.post("/api/scans/upload", files=files, data=data)
    print(f"\n{'='*50}")
    print(f"TEST: {label}")
    print(f"  upload status: {r.status_code}")
    if r.status_code in (200, 201, 202):
        body = r.json()
        print(f"  response: {json.dumps(body, indent=2)}")
        return r.status_code, body
    else:
        print(f"  error: {r.text}")
        return r.status_code, r.text


def get_scan(scan_id):
    """GET scan details and return json."""
    r = client.get(f"/api/scans/{scan_id}")
    return r.json()


passed = 0
failed = 0

# ─── Test 1: No scan_mode (default) ───
code, body = upload(scan_mode_param=None, label="Test 1: No scan_mode (default)")
if code == 202:
    scan = get_scan(body["scan_id"])
    if scan["scan_mode"] == "static" and scan["dynamic_status"] == "not_requested":
        print("  ✅ PASS: scan_mode=static, dynamic_status=not_requested")
        passed += 1
    else:
        print(f"  ❌ FAIL: scan_mode={scan['scan_mode']}, dynamic_status={scan['dynamic_status']}")
        failed += 1
else:
    print("  ❌ FAIL: Upload failed")
    failed += 1

# ─── Test 2: scan_mode="static" ───
code, body = upload(scan_mode_param="static", label="Test 2: scan_mode='static'")
if code == 202:
    scan = get_scan(body["scan_id"])
    if scan["scan_mode"] == "static" and scan["dynamic_status"] == "not_requested":
        print("  ✅ PASS: scan_mode=static, dynamic_status=not_requested")
        passed += 1
    else:
        print(f"  ❌ FAIL: scan_mode={scan['scan_mode']}, dynamic_status={scan['dynamic_status']}")
        failed += 1
else:
    print("  ❌ FAIL: Upload failed")
    failed += 1

# ─── Test 3: scan_mode="dynamic" ───
code, body = upload(scan_mode_param="dynamic", label="Test 3: scan_mode='dynamic'")
if code == 202:
    scan = get_scan(body["scan_id"])
    if scan["scan_mode"] == "dynamic" and scan["dynamic_status"] == "queued" and scan["dynamic_error"] is None:
        print("  ✅ PASS: scan_mode=dynamic, dynamic_status=queued, dynamic_error=None")
        passed += 1
    else:
        print(f"  ❌ FAIL: scan_mode={scan['scan_mode']}, dynamic_status={scan['dynamic_status']}, dynamic_error={scan['dynamic_error']}")
        failed += 1
else:
    print("  ❌ FAIL: Upload failed")
    failed += 1

# ─── Test 4: Invalid scan_mode ───
code, body = upload(scan_mode_param="fuzz", label="Test 4: scan_mode='fuzz' (invalid)")
if code == 422:
    print("  ✅ PASS: HTTP 422 returned for invalid scan_mode")
    passed += 1
else:
    print(f"  ❌ FAIL: Expected 422, got {code}")
    failed += 1

print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed out of 4 tests")
if failed > 0:
    sys.exit(1)
