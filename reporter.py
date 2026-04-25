# forensic/reporter.py

import os
from datetime import datetime

REPORT_DIR = "data/reports"

def generate_report(case_id, findings):
    os.makedirs(REPORT_DIR, exist_ok=True)

    filename = f"{case_id}_report.txt"
    path = os.path.join(REPORT_DIR, filename)

    with open(path, "w") as f:
        f.write("=== DIGITAL FORENSIC REPORT ===\n")
        f.write(f"Case ID: {case_id}\n")
        f.write(f"Timestamp: {datetime.now()}\n\n")

        for key, value in findings.items():
            f.write(f"{key}: {value}\n")

    return path