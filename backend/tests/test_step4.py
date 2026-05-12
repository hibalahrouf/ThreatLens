"""
Step 4 — Verification tests for post-static dynamic trigger.
"""
import ast
import sys

PASS = 0
FAIL = 0


def check(name, condition):
    global PASS, FAIL
    if condition:
        print(f"  [PASS] {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}")
        FAIL += 1


# ── scan_tasks.py ──
print("\n=== scan_tasks.py ===")
src = open("app/tasks/scan_tasks.py", encoding="utf-8").read()

# Syntax check
try:
    ast.parse(src)
    check("Syntax valid", True)
except SyntaxError as e:
    check(f"Syntax valid ({e})", False)

check(
    'Contains scan_mode == "dynamic" guard',
    'scan.scan_mode == "dynamic"' in src,
)
check(
    "Contains dynamic_scan_orchestrator.delay(scan_id)",
    "dynamic_scan_orchestrator.delay(scan_id)" in src,
)
check(
    "Contains import of dynamic_scan_orchestrator",
    "from app.tasks.dynamic_scan_tasks import dynamic_scan_orchestrator" in src,
)

# Ordering: DONE must appear BEFORE the dynamic trigger
done_idx = src.index("ScanStatus.DONE")
trigger_idx = src.index('scan.scan_mode == "dynamic"')
check("Dynamic trigger is AFTER ScanStatus.DONE", done_idx < trigger_idx)

# Ensure dynamic trigger is BEFORE the return statement (within try block)
return_idx = src.index('return {"scan_id"')
check("Dynamic trigger is BEFORE return", trigger_idx < return_idx)

# Ensure existing static steps are not modified
check("Step 1 (mark running) intact", "Step 1: Mark as running" in src)
check("Step 4 (MASVS mapping) intact", "Step 4: Map findings to MASVS" in src)
check("Step 9 (LLM Triage) intact", "Step 9: LLM Triage" in src)
check("Step 10 (LLM Remediation) intact", "Step 10: LLM Auto-Remediation" in src)
check("Step 11 (Global score) intact", "Step 11: Calculate global score" in src)
check("pdf_generator NOT imported", "pdf_generator" not in src)


# ── scans.py ──
print("\n=== scans.py ===")
src2 = open("app/api/scans.py", encoding="utf-8").read()

try:
    ast.parse(src2)
    check("Syntax valid", True)
except SyntaxError as e:
    check(f"Syntax valid ({e})", False)

check("TODO comment removed", "TODO" not in src2)
check(
    "New comment present",
    "Dynamic pipeline is triggered automatically by scan_orchestrator" in src2,
)
check(
    "dynamic_scan_orchestrator.delay NOT in scans.py",
    "dynamic_scan_orchestrator.delay" not in src2,
)
check(
    'dynamic_status = "queued" for dynamic mode',
    '"queued" if scan_mode == "dynamic" else "not_requested"' in src2,
)
check(
    "scan_mode field set on Scan creation",
    "scan_mode=scan_mode," in src2,
)
check(
    "dynamic_status field set on Scan creation",
    "dynamic_status=dynamic_status," in src2,
)

# ── Summary ──
print(f"\n{'='*40}")
print(f"Results: {PASS} passed, {FAIL} failed")
if FAIL > 0:
    sys.exit(1)
else:
    print("All checks PASSED!")
