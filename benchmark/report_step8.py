import csv
import json

RESULTS_CSV = "benchmark/results/summary.csv"
AUDIT_LOGS_CSV = "benchmark/audit_logs.csv"
GROUND_TRUTH_JSON = "benchmark/ground_truth.json"

def main():
    # 1. SHA-256 for each APK (hardcoded from Step 1)
    print("--- 1. SHA-256 Hashes ---")
    print("DivaApplication.apk: 5CEFC51FCE9BD760B92AB2340477F4DDA84B4AE0C5D04A8C9493E4FE34FAB7C5")
    print("InsecureBankv2.apk: B18AF2A0E44D7634BBCDF93664D9C78A2695E050393FCFBB5E8B91F902D194A4")
    print("UnCrackable-Level1.apk: 1DA8BF57D266109F9A07C01BF7111A1975CE01F190B9D914BCD3AE3DBEF96F21")
    print("UnCrackable-Level3.apk: 6827F776B7D2844342711BE6F13695AE8D1A5F209FC0072DBAF8B85E2FCFF4B7\n")

    # Load results
    scans = []
    with open(RESULTS_CSV, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            scans.append(row)

    # 2. Mean scan time
    total_time = sum(int(s["scan_duration_seconds"]) for s in scans)
    mean_time = total_time / len(scans) if scans else 0
    print(f"--- 2. Mean ThreatLens Scan Time ---")
    print(f"{mean_time:.2f} seconds ({mean_time/60:.2f} minutes)\n")

    # 3. Precision, Recall, F1 vs Ground Truth
    with open(GROUND_TRUTH_JSON, "r") as f:
        gt_data = json.load(f)

    # Calculate metrics
    TP, FP, FN, TN = 0, 0, 0, 0
    for apk_data in gt_data:
        for finding in apk_data["findings"]:
            ai_verdict = finding["ai_verdict"]
            actual = finding["ground_truth"]
            
            if ai_verdict == "true_positive" and actual == "true_positive":
                TP += 1
            elif ai_verdict == "true_positive" and actual == "false_positive":
                FP += 1
            elif ai_verdict == "false_positive" and actual == "true_positive":
                FN += 1
            elif ai_verdict == "false_positive" and actual == "false_positive":
                TN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("--- 3. AI Triage Metrics (vs Ground Truth) ---")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"(TP={TP}, FP={FP}, FN={FN}, TN={TN})\n")

    # 4. Manual audit time vs ThreatLens time per APK
    print("--- 4. Time Comparison (Manual vs AI) ---")
    manual_logs = []
    with open(AUDIT_LOGS_CSV, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            manual_logs.append(row)

    for s in scans:
        apk = s["apk_name"]
        ai_time_sec = int(s["scan_duration_seconds"])
        ai_time_min = ai_time_sec / 60.0
        
        manual_time_min = 0
        for m in manual_logs:
            if m["apk_name"] == apk:
                manual_time_min = float(m["time_minutes"])
                break
                
        print(f"{apk}:")
        print(f"  - Manual Audit (Baseline): {manual_time_min:.1f} minutes")
        print(f"  - ThreatLens (Automated):  {ai_time_min:.1f} minutes")
        print(f"  - Speedup:                 {manual_time_min / ai_time_min if ai_time_min > 0 else 0:.1f}x faster\n")

    # 5. Number of MASVS controls covered per APK
    print("--- 5. MASVS Controls Covered ---")
    for s in scans:
        controls = s["masvs_controls_covered"].split("|") if s["masvs_controls_covered"] else []
        print(f"{s['apk_name']}: {len(controls)} unique controls covered")

if __name__ == "__main__":
    main()
