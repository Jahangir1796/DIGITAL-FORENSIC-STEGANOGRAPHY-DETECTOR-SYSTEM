# forensic/detector.py

from PIL import Image
import numpy as np

def lsb_analysis(image_path):
    img = Image.open(image_path)
    pixels = np.array(img)

    # Extract LSBs
    lsb = pixels & 1

    # Calculate ratio of 0s and 1s
    zeros = np.sum(lsb == 0)
    ones = np.sum(lsb == 1)

    total = zeros + ones
    ratio = ones / total

    return ratio


def detect_stego(image_path, threshold=0.5):
    ratio = lsb_analysis(image_path)

    # In natural images, LSBs are not perfectly random
    if 0.45 < ratio < 0.55:
        return True, ratio
    return False, ratio