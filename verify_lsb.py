
from lsb_engine import encode_lsb, decode_lsb
from PIL import Image
import numpy as np
import os

# Create dummy image
img = Image.new('RGB', (100, 100), color = 'red')
img.save('test_src.png')

data = "Secret Message 123"
pwd = "password"

print("1. Encoding...")
success = encode_lsb('test_src.png', data, 'test_stego.png', pwd)
print(f"Encode Success: {success}")

print("2. Decoding...")
decoded = decode_lsb('test_stego.png', pwd)
print(f"Decoded Raw: {decoded}")
try:
    print(f"Decoded Text: {decoded.decode()}")
except:
    print("Decoded bytes not utf-8")

if decoded.decode() == data:
    print("✅ TEST PASSED")
else:
    print("❌ TEST FAILED")
