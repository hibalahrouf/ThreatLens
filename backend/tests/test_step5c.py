"""
Step 5C -- Verification tests for PDF generator dynamic summary changes.
Only checks pdf_generator.py. Does NOT touch any other file.
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

print("\n=== pdf_generator.py ===")
src = open("app/reports/pdf_generator.py", encoding="utf-8").read()

# Syntax
try:
    ast.parse(src)
    check("Syntax valid", True)
except SyntaxError as e:
    check(f"Syntax valid ({e})", False)

# Template block logic
check("scan_mode passed to template check", "{% if scan_mode == 'dynamic' %}" in src)
check("dynamic_status passed to template", "dynamic_status" in src)
check("dynamic-summary-block class exists", 'class="dynamic-summary-block"' in src)
check("dynamic completed status", "dynamic_status == 'completed'" in src)
check("dynamic running/queued status", "dynamic_status in ['running', 'queued']" in src)
check("dynamic failed status", "dynamic_status == 'failed'" in src)
check("Null-safe error check", "dynamic_error if dynamic_error else" in src)

# Styling
check("left border blue present", "border-left:4px solid #4A90D9" in src)
check("Title is Dynamic Analysis", ">Dynamic Analysis</h3>" in src)
check("Count formatting", "Network ({{ count_network }}) &middot; Dynamic ({{ count_dynamic }}) &middot; Frida ({{ count_frida }})" in src)

# Ensure sections haven't moved
check("Section order unchanged (Exec summary -> Security posture)", 
      src.index("2. EXECUTIVE SUMMARY") < src.index("dynamic-summary-block") < src.index("3. SECURITY POSTURE"))

print(f"\n{'='*40}")
print(f"Results: {PASS} passed, {FAIL} failed")
if FAIL > 0:
    sys.exit(1)
else:
    print("All checks PASSED!")
