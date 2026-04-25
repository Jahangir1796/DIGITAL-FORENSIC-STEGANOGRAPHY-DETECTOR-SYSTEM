from cryptography.fernet import Fernet
import base64
import hashlib
import os

def generate_salt():
    """Generate a random 16-byte salt."""
    return os.urandom(16)

def generate_key(password, salt):
    """Derive a 32-byte key from the password and salt using SHA-256."""
    key_material = password.encode() + salt
    hashed_key = hashlib.sha256(key_material).digest()
    return base64.urlsafe_b64encode(hashed_key)

def encrypt_message(message, password):
    """Encrypt the message with a salted key."""
    salt = generate_salt()
    key = generate_key(password, salt)
    fernet = Fernet(key)
    
    # Handle file paths vs text messages
    if isinstance(message, str):
        if message.endswith('.txt'):
            # Read and encrypt the file contents
            try:
                with open(message, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                # Prepend marker to indicate it's a file
                data_to_encrypt = f"FILE:TXT:{file_content}"
            except Exception as e:
                raise ValueError(f"Error reading text file: {e}")
        elif message.endswith('.pdf'):
            # Read and encrypt the PDF file path (since PDFs are binary)
            try:
                with open(message, 'rb') as f:
                    file_content = f.read()
                # Store as base64 to handle binary data
                data_to_encrypt = f"FILE:PDF:{base64.b64encode(file_content).decode()}"
            except Exception as e:
                raise ValueError(f"Error reading PDF file: {e}")
        else:
            # Just a text message
            data_to_encrypt = f"TEXT:{message}"
    else:
        data_to_encrypt = f"TEXT:{message}"
    
    encrypted_data = fernet.encrypt(data_to_encrypt.encode())
    # Return encrypted data with salt prepended
    return salt + encrypted_data

def decrypt_message(encrypted_message, password):
    """Decrypt the message using the stored salt."""
    try:
        # Extract salt (first 16 bytes) and encrypted data
        salt = encrypted_message[:16]
        encrypted_data = encrypted_message[16:]
        key = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data).decode()
        
        # Parse the decrypted data
        if decrypted.startswith("FILE:TXT:"):
            return decrypted[9:]  # Return the file content
        elif decrypted.startswith("FILE:PDF:"):
            # Return base64 decoded PDF content indication
            return f"[PDF File Content - {len(decrypted)} bytes]"
        elif decrypted.startswith("TEXT:"):
            return decrypted[5:]  # Return the text message
        else:
            return decrypted
            
    except Exception as e:
        return f"[Decryption Failed: {str(e)}]"