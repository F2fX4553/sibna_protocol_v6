import os
import hashlib
from sibna import SecureContext, Config

# Mocking sibna for demonstration
try:
    from sibna import SecureContext, Config
except ImportError:
    class Config: pass
    class SecureContext:
        def __init__(self, cfg, password): pass
        def encrypt_message(self, peer, data): return b"ENC:" + data
        def decrypt_message(self, peer, data): return data[4:]

def encrypt_file(file_path, recipient_id, output_path=None):
    if not output_path:
        output_path = file_path + ".sibna"
        
    print(f"🔒 Encrypting: {file_path} for {recipient_id}...")
    
    config = Config()
    ctx = SecureContext(config, password=b"vault_key_123")
    
    with open(file_path, "rb") as f:
        data = f.read()
        
    original_hash = hashlib.sha256(data).hexdigest()
    print(f"📄 Original SHA256: {original_hash}")
    
    # Encrypt the entire file buffer
    encrypted_data = ctx.encrypt_message(recipient_id, data)
    
    with open(output_path, "wb") as f:
        f.write(encrypted_data)
        
    print(f"📂 Saved to: {output_path}")
    return output_path

def decrypt_file(file_path, sender_id, output_path=None):
    if not output_path:
        output_path = file_path.replace(".sibna", ".decrypted")
        
    print(f"🔓 Decrypting: {file_path} from {sender_id}...")
    
    config = Config()
    ctx = SecureContext(config, password=b"vault_key_123")
    
    with open(file_path, "rb") as f:
        data = f.read()
        
    decrypted_data = ctx.decrypt_message(sender_id, data)
    
    with open(output_path, "wb") as f:
        f.write(decrypted_data)
        
    restored_hash = hashlib.sha256(decrypted_data).hexdigest()
    print(f"📄 Restored SHA256: {restored_hash}")
    print(f"✅ File successfully decrypted to: {output_path}")

if __name__ == "__main__":
    # Demo use case
    test_file = "vault_test.txt"
    with open(test_file, "w") as f:
        f.write("Highly sensitive protocol documentation. Do not distribute.")
    
    enc_path = encrypt_file(test_file, "Bob")
    decrypt_file(enc_path, "Bob")
    
    # Clean up
    if os.path.exists(test_file): os.remove(test_file)
