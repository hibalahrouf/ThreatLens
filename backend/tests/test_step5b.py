"""
Step 5B -- Verification tests for PDF generator changes.
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

# Task 1: Source badges in template
check("DYNAMIC badge present (color #E67E22)", "#E67E22" in src and "DYNAMIC" in src)
check("FRIDA badge present (color #8E44AD)", "#8E44AD" in src and "FRIDA" in src)
check("NETWORK badge present (color #27AE60)", "#27AE60" in src and "NETWORK" in src)
check("Badge for 'dynamic' source", "f.source == 'dynamic'" in src)
check("Badge for 'frida' source", "f.source == 'frida'" in src)
check("Badge for 'network' source", "f.source == 'network'" in src)
check("No badge for 'static' source", "f.source == 'static'" not in src)

# Task 2: Methodology line
check("scan_mode from scan_data", 'scan_data.get("scan_mode")' in src)
check("has_frida computation", 'has_frida = any(' in src)
check("Methodology: static only", 'methodology_line = "Static Analysis: MobSF"' in src)
check("Methodology: dynamic", '"Static Analysis: MobSF + Dynamic Analysis: MobSF Runtime"' in src)
check("Methodology: dynamic + frida", '"Static Analysis: MobSF + Dynamic Analysis: MobSF Runtime + Frida"' in src)
check("methodology_line passed to template", "methodology_line=methodology_line" in src)
check("scan_mode passed to template", "scan_mode=scan_mode" in src)
check("has_frida passed to template", "has_frida=has_frida" in src)
check("{{ methodology_line }} in template", "{{ methodology_line }}" in src)

# Methodology table rows
check("Dynamic Analysis row in table", "Dynamic Analysis</td><td>MobSF Runtime" in src)
check("Frida row in table", "Instrumentation</td><td>Frida" in src)
check("Frida row guarded by has_frida", "and has_frida" in src)

# Task 3: No source filter in compliance matrix (verified in report_helpers.py)
helpers_src = open("app/reports/report_helpers.py", encoding="utf-8").read()
check("No 'source' filtering in report_helpers (compliance matrix)", "source" not in helpers_src)

# Constraints
check("Section order unchanged (Cover before Exec before Findings before Matrix before Methodology)",
      src.index("1. COVER") < src.index("2. EXECUTIVE") < src.index("6. TECHNICAL FINDINGS") < src.index("7. COMPLIANCE MATRIX") < src.index("8. METHODOLOGY"))
check("No dynamic summary block added (Step 5C)", "Dynamic Summary" not in src and "dynamic_summary" not in src)

# Null safety
check("Null-safe source check (f.get('source') or '')", '(f.get("source") or "")' in src)
check("Null-safe scan_mode (scan_data.get or static)", 'or "static"' in src)

print(f"\n{'='*40}")
print(f"Results: {PASS} passed, {FAIL} failed")
if FAIL > 0:
    sys.exit(1)
else:
    print("All checks PASSED!")
