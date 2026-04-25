# forensic/analyzer.py

from PIL import Image
import numpy as np
from math import log2

def calculate_entropy(image_path):
    img = Image.open(image_path).convert("L")  # grayscale
    pixels = np.array(img).flatten()

    histogram = np.bincount(pixels, minlength=256)
    probabilities = histogram / len(pixels)

    entropy = -sum(p * log2(p) for p in probabilities if p > 0)
    return entropy


def analyze_image(image_path):
    entropy = calculate_entropy(image_path)

    result = {
        "entropy": entropy,
        "suspicious": entropy > 7.5  # heuristic threshold
    }

    return result