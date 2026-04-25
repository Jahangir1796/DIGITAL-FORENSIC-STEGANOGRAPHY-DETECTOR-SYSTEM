from PIL import Image
import numpy as np
import hashlib

def encode_lsb(image_path, data, output_path, password=None):
    """Encode data into image using robust LSB Replacement with Length Header."""
    try:
        img = Image.open(image_path)
        if img.mode != 'RGB': img = img.convert('RGB')
        
        pixels = np.array(img, dtype=np.uint8)
        pixels_flat = pixels.flatten()
        
        # Prepare Data: [Length (32-bit big endian)] + [Data]
        length_bytes = len(data).to_bytes(4, byteorder='big')
        full_data = length_bytes + data.encode() if isinstance(data, str) else length_bytes + data
        
        # Convert to bits
        binary_bits = np.unpackbits(np.frombuffer(full_data, dtype=np.uint8))
        required_bits = len(binary_bits)
        
        if required_bits > pixels.size:
            raise ValueError(f"Image too small. Need {required_bits} pixels.")
            
        # Determine indices
        if password:
            seed = int(hashlib.sha256(password.encode()).hexdigest(), 16) % 2**32
            np.random.seed(seed)
            indices = np.random.permutation(len(pixels_flat))[:required_bits]
        else:
            indices = np.arange(required_bits)
            
        # Embed Bits (LSB Replacement)
        # Clear LSB ( & 0xFE ) then OR with bit
        pixels_flat[indices] = (pixels_flat[indices] & 0xFE) | binary_bits
        
        encoded_img = Image.fromarray(pixels_flat.reshape(pixels.shape))
        encoded_img.save(output_path, 'PNG')
        return True
        
    except Exception as e:
        print(f"Encoding error: {str(e)}")
        return False

def decode_lsb(image_path, password=None):
    """Decode data from image using Length Header."""
    try:
        img = Image.open(image_path)
        if img.mode != 'RGB': img = img.convert('RGB')
        pixels = np.array(img, dtype=np.uint8).flatten()
        
        # 1. Read Length (First 32 bits / 4 bytes)
        length_bits_count = 32
        
        if password:
            seed = int(hashlib.sha256(password.encode()).hexdigest(), 16) % 2**32
            np.random.seed(seed)
            # Re-generate full permutation to find the first 32 positions (and then the rest)
            full_indices = np.random.permutation(len(pixels))
            indices_len = full_indices[:32]
        else:
            full_indices = np.arange(len(pixels))
            indices_len = full_indices[:32]
            
        # Extract Length bits
        len_bits = (pixels[indices_len] & 1)
        length_val = int.from_bytes(np.packbits(len_bits).tobytes(), byteorder='big')
        
        # Sanity check length
        if length_val <= 0 or length_val > len(pixels)*3: # formatting error
            return b''
            
        # 2. Read Data
        total_data_bits = length_val * 8
        if password:
            # Continue from the next indices in the SAME permutation sequence
            indices_data = full_indices[32 : 32 + total_data_bits]
        else:
            indices_data = full_indices[32 : 32 + total_data_bits]
            
        data_bits = (pixels[indices_data] & 1)
        bytes_data = np.packbits(data_bits).tobytes()
        
        return bytes_data
    
    except Exception as e:
        print(f"Decoding error: {str(e)}")
        return b''