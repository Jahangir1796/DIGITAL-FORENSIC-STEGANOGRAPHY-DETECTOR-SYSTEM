# main_forensic.py

from detector import detect_stego
from analyzer import analyze_image
from extractor import forensic_extract
from integrity import compute_hash
from case_manager import create_case, add_evidence
from reporter import generate_report


def run_forensic(image_path):
    # Step 1: Create Case
    case_id, case_path = create_case("stego_case")

    # Step 2: Add Evidence
    evidence_path = add_evidence(case_path, image_path)

    # Step 3: Integrity Check
    file_hash = compute_hash(evidence_path)

    # Step 4: Detection
    is_stego, ratio = detect_stego(evidence_path)

    # Step 5: Analysis
    analysis = analyze_image(evidence_path)

    # Step 6: Extraction
    extraction = forensic_extract(evidence_path)

    # Step 7: Report
    findings = {
        "Hash": file_hash,
        "Stego Detected": is_stego,
        "LSB Ratio": ratio,
        "Entropy": analysis["entropy"],
        "Extracted Data": extraction.get("data", "None")
    }

    report_path = generate_report(case_id, findings)

    print(f"[+] Report Generated: {report_path}")


if __name__ == "__main__":
    run_forensic("stegtest2.png")