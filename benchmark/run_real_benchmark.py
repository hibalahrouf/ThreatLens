import os
import time
import json
import csv
import httpx
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0IiwiZXhwIjoxNzc4NDQ5NzcwLCJ0eXBlIjoiYWNjZXNzIn0.r5PYECjYLsqNXKcxZeN-W_yd3o2Bf5-aUSOmGOMtAH8"
APKS = [
    "docs/samples/DivaApplication.apk",
    "docs/samples/InsecureBankv2.apk",
    "docs/samples/UnCrackable-Level1.apk",
    "docs/samples/UnCrackable-Level3.apk"
]
RESULTS_DIR = "benchmark/results"
SUMMARY_FILE = os.path.join(RESULTS_DIR, "summary.csv")

def upload_and_scan(apk_path):
    print(f"Uploading {apk_path}...")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    with open(apk_path, "rb") as f:
        files = {"file": (os.path.basename(apk_path), f)}
        data = {"project_name": "Benchmark_Real"}
        resp = httpx.post(f"{BASE_URL}/api/scans/upload", headers=headers, files=files, data=data, timeout=600)
    
    if resp.status_code != 202:
        print(f"Upload failed for {apk_path}: {resp.text}")
        return None
    
    return resp.json()["scan_id"]

def wait_for_scan(scan_id):
    print(f"Waiting for scan {scan_id} to complete...")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    while True:
        resp = httpx.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers)
        if resp.status_code != 200:
            print(f"Error fetching scan {scan_id}: {resp.text}")
            return None
        
        data = resp.json()
        status = data["status"]
        progress = data.get("progress", 0)
        print(f"Scan {scan_id} status: {status} ({progress}%)")
        
        if status == "done":
            return data
        if status == "failed":
            print(f"Scan {scan_id} failed: {data.get('error_message')}")
            return data
        
        time.sleep(5)

def get_findings(scan_id):
    headers = {"Authorization": f"Bearer {TOKEN}"}
    resp = httpx.get(f"{BASE_URL}/api/scans/{scan_id}/findings", headers=headers)
    if resp.status_code != 200:
        return []
    return resp.json()

def main():
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    results = []
    
    for apk in APKS:
        scan_id = upload_and_scan(apk)
        if not scan_id:
            continue
        
        scan_data = wait_for_scan(scan_id)
        if not scan_data or scan_data["status"] != "done":
            continue
        
        findings = get_findings(scan_id)
        
        # Calculate metrics
        total_findings = len(findings)
        ai_tp = len([f for f in findings if f.get("triage_result") == "true_positive"])
        ai_fp = len([f for f in findings if f.get("triage_result") == "false_positive"])
        
        # Unique MASVS controls
        controls = sorted(list(set([f["masvs_control"] for f in findings if f.get("masvs_control")])))
        
        started_at = scan_data.get("started_at")
        completed_at = scan_data.get("completed_at")
        
        # Parse timestamps to calculate duration if not provided
        duration = 0
        if started_at and completed_at:
            # Example: 2026-05-10T20:00:00.000Z
            fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
            try:
                start_dt = datetime.strptime(started_at.split(".")[0] + "Z", "%Y-%m-%dT%H:%M:%SZ")
                end_dt = datetime.strptime(completed_at.split(".")[0] + "Z", "%Y-%m-%dT%H:%M:%SZ")
                duration = (end_dt - start_dt).total_seconds()
            except:
                pass

        results.append({
            "apk_name": os.path.basename(apk),
            "started_at": started_at,
            "completed_at": completed_at,
            "scan_duration_seconds": duration,
            "total_findings": total_findings,
            "ai_tp_count": ai_tp,
            "ai_fp_count": ai_fp,
            "masvs_controls_covered": "|".join(controls)
        })

    # Write to CSV
    keys = results[0].keys()
    with open(SUMMARY_FILE, "w", newline="") as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)
    
    print(f"Benchmark results saved to {SUMMARY_FILE}")

if __name__ == "__main__":
    main()
