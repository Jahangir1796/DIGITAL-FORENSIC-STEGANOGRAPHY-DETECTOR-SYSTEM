# forensic/extractor.py

from lsb_engine import decode_lsb

def forensic_extract(image_path):
    try:
        data = decode_lsb(image_path)

        if data:
            return {
                "found": True,
                "data": data
            }
        else:
            return {"found": False}

    except Exception as e:
        return {
            "found": False,
            "error": str(e)
        }