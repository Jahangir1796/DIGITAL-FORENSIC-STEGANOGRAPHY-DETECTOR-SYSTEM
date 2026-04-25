# forensic/integrity.py

import hashlib

def compute_hash(file_path, algo="sha256"):
    hash_func = hashlib.new(algo)

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)

    return hash_func.hexdigest()