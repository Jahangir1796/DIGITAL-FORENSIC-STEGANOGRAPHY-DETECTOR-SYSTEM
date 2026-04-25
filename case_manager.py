# forensic/case_manager.py

import os
import shutil
from datetime import datetime

BASE_DIR = "data/cases"

def create_case(case_name):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_id = f"{case_name}_{timestamp}"

    case_path = os.path.join(BASE_DIR, case_id)
    os.makedirs(case_path, exist_ok=True)

    return case_id, case_path


def add_evidence(case_path, file_path):
    filename = os.path.basename(file_path)
    dest = os.path.join(case_path, filename)
    shutil.copy(file_path, dest)

    return dest