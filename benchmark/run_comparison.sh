#!/bin/bash
# ThreatLens Benchmark - Multi-tool Comparison (Windows/Git Bash Compatible)

set -e

BASE_URL="http://localhost:8000"
# Extract token using Python for portability
TOKEN=$(python -c "import os; import tomli; path=os.path.expanduser('~/.masvs/config.toml'); print(tomli.load(open(path, 'rb'))['token'])" 2>/dev/null || echo "")

RESULTS_DIR="benchmark/results"
SUMMARY_FILE="$RESULTS_DIR/comparison_summary.csv"

if [ -z "$TOKEN" ]; then
    echo "Error: CLI token not found. Run 'masvs auth login' first."
    exit 1
fi

mkdir -p "$RESULTS_DIR"

echo "apk_name,mobsf_raw_findings,threatlens_tp_findings,reduction_rate,duration_sec" > "$SUMMARY_FILE"

APKS=(
    "docs/samples/DivaApplication.apk"
    "docs/samples/InsecureBankv2.apk"
    "docs/samples/UnCrackable-Level1.apk"
    "docs/samples/UnCrackable-Level3.apk"
)

for APK in "${APKS[@]}"; do
    if [ ! -f "$APK" ]; then
        echo "Skipping $APK (not found)"
        continue
    fi

    echo "--------------------------------------------------"
    echo "Processing $APK..."
    
    START_TIME=$(date +%s)
    # Get scan result directly from API if already processed, otherwise run it
    # For benchmark, we assume they are already run or we run them now
    SCAN_OUTPUT=$(threatlens scan run "$APK" --project "Comparison_Test" --output json --wait)
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    # Extract Scan ID from output
    SCAN_ID=$(echo "$SCAN_OUTPUT" | grep -oP "Scan ID: \K\d+")
    
    if [ -z "$SCAN_ID" ]; then
        # Fallback for different grep versions
        SCAN_ID=$(echo "$SCAN_OUTPUT" | grep "Scan ID:" | awk '{print $NF}')
    fi

    if [ -z "$SCAN_ID" ]; then
        echo "Error: Could not extract Scan ID for $APK"
        continue
    fi

    # Get findings from API
    FINDINGS_JSON=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/scans/$SCAN_ID/findings")
    
    # Count IDs (simple count)
    RAW_COUNT=$(echo "$FINDINGS_JSON" | grep -o "\"id\":" | wc -l)
    TP_COUNT=$(echo "$FINDINGS_JSON" | grep -o "\"triage_result\": \"true_positive\"" | wc -l)
    
    if [ "$RAW_COUNT" -gt 0 ]; then
        REDUCTION=$(python -c "print(f'{((($RAW_COUNT - $TP_COUNT) / $RAW_COUNT) * 100):.1f}%')")
    else
        REDUCTION="0.0%"
    fi

    echo "APK: $(basename "$APK")"
    echo "MobSF Raw: $RAW_COUNT"
    echo "ThreatLens TP: $TP_COUNT"
    echo "Alert Reduction: $REDUCTION"
    echo "Time: ${DURATION}s"

    echo "$(basename "$APK"),$RAW_COUNT,$TP_COUNT,$REDUCTION,$DURATION" >> "$SUMMARY_FILE"
done

echo "--------------------------------------------------"
echo "Benchmark complete. Results saved to $SUMMARY_FILE"
