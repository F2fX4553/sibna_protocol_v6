from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from typing import List, Dict, Optional
import uvicorn
import sqlite3
import time
import re
from collections import defaultdict

app = FastAPI(docs_url=None, redoc_url=None)

# --- Security Configuration ---
MAX_REQ_PER_MINUTE = 60
MESSAGE_TTL = 86400 # 24 hours in seconds
DB_PATH = "server_keys.db"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            identity_key TEXT NOT NULL,
            signed_pre_key TEXT NOT NULL,
            signed_pre_key_sig TEXT NOT NULL,
            last_seen REAL
        )
    ''')
    
    # One-Time Keys Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS one_time_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            key_data TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_otk_user ON one_time_keys(user_id)')
    
    # Messages Table (Encrypted Relays)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id TEXT,
            sender_id TEXT,
            content TEXT NOT NULL,
            timestamp REAL,
            FOREIGN KEY(recipient_id) REFERENCES users(user_id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_msg_timestamp ON messages(timestamp)')
    
    conn.commit()
    conn.close()

init_db()

# --- Background Tasks: Cleanup ---
import threading

def purge_expired_messages():
    """Periodically remove messages older than MESSAGE_TTL"""
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cutoff = time.time() - MESSAGE_TTL
            cursor.execute('DELETE FROM messages WHERE timestamp < ?', (cutoff,))
            count = cursor.rowcount
            conn.commit()
            conn.close()
            if count > 0:
                print(f"[Cleanup] Purged {count} expired messages.")
        except Exception as e:
            print(f"[Cleanup Error] {e}")
        
        time.sleep(3600) # Run every hour

cleanup_thread = threading.Thread(target=purge_expired_messages, daemon=True)
cleanup_thread.start()


# --- Middleware: Rate Limiting (DoS Protection) ---
# Simple in-memory rate limiter. For production scaling, use Redis.
request_counts = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    now = time.time()
    
    # Clean up old requests
    request_counts[client_ip] = [t for t in request_counts[client_ip] if t > now - 60]
    
    if len(request_counts[client_ip]) >= MAX_REQ_PER_MINUTE:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded. Try again later."}
        )
    
    
    request_counts[client_ip].append(now)
    response = await call_next(request)
    return response

# --- Middleware: Security Headers (HSTS, etc.) ---
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # HSTS (Strict-Transport-Security): Force HTTPS for 1 year (only works if served over HTTPS)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Anti-Clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Anti-MIME Sniffing (Redundant with our middleware, but good practice)
    response.headers["X-Content-Type-Options"] = "nosniff"
    # XSS Protection (Legacy but harmless)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# --- Middleware: Payload Size Limit (Memory Exhaustion Protection) ---
MAX_PAYLOAD_SIZE = 1024 * 1024 # 1MB

@app.middleware("http")
async def limit_payload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_PAYLOAD_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Payload too large. Max 1MB."}
        )
    return await call_next(request)

# --- Middleware: Strict Content-Type (MIME Sniffing Protection) ---
@app.middleware("http")
async def strict_content_type(request: Request, call_next):
    if request.method in ["POST", "PUT", "PATCH"]:
        ct = request.headers.get("content-type", "")
        if "application/json" not in ct:
            return JSONResponse(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                content={"detail": "Unsupported Media Type. Use application/json"}
            )
    return await call_next(request)

# --- Models & Validation ---
# ... (Previous Models code is fine, omitted for brevity if unchanged by tool logic, but I need to be careful with replace tool context)
# Actually, the user wants me to edit the END of the file to remove /users and add headers.
# I will use replace_file on the specific chunks.

# ...
    
if __name__ == "__main__":
    # Disable Docs in Production
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")


# --- Models & Validation ---
class PreKeyBundle(BaseModel):
    user_id: str
    identity_key: str  # Hex encoded, 64 chars
    signed_pre_key: str # Hex encoded, 64 chars
    signed_pre_key_sig: str # Hex encoded, 128 chars
    one_time_pre_keys: List[str] # List of Hex encoded keys

    @validator('user_id')
    def validate_user_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', v):
            raise ValueError('Invalid user_id format')
        return v
        
    @validator('identity_key', 'signed_pre_key')
    def validate_32byte_hex(cls, v):
        if len(v) != 64 or not re.match(r'^[0-9a-fA-F]+$', v):
            raise ValueError('Key must be 32 bytes hex')
        return v

class PreKeyResponse(BaseModel):
    identity_key: str
    signed_pre_key: str
    signed_pre_key_sig: str
    one_time_pre_key: Optional[str] = None

# --- Crypto Helpers ---
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def verify_signature(identity_key_hex: str, data_hex: str, signature_hex: str) -> bool:
    try:
        # X3DH uses X25519 for keys, but signatures require Ed25519.
        # In this simplified protocol, we are assuming Identity Key is X25519 
        # but for signing we need Ed25519. Converting is hard/impossible safely.
        # usually Identity Key IS Ed25519, and we convert to X25519 for DH.
        
        # HOWEVER, the user's current Python fallback uses X25519 directly.
        # X25519 cannot sign. 
        # This is a dilemma. The "Fake" Python part used X25519.
        # To be "Real", we should use Ed25519 for Identity.
        
        # For this tasks' scope ("Hardening"), we will mock the verification 
        # IF we can't easily switch keys.
        # BUT, the user wants "Real".
        
        # Let's assume the client sends valid Ed25519 keys for Identity now?
        # Or we use a signing-capable library?
        
        # Wait, Signal Protocol uses X25519 for everything implies using XEdDSA 
        # or having separate signing keys.
        
        # Let's look at what `resilient_messenger` or `key_client` generates.
        # `key_client` generates dummy bytes.
        
        # I will implement a "Simulated" Verification if libraries mismatch, 
        # BUT enforcing the check is the key.
        
        # For "The Real Deal", I'll assume standard Ed25519 for identity.
        from cryptography.hazmat.primitives.asymmetric import ed25519
        
        id_key_bytes = bytes.fromhex(identity_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        data_bytes = bytes.fromhex(data_hex)
        
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(id_key_bytes)
        public_key.verify(sig_bytes, data_bytes)
        return True
    except Exception:
        return False

# --- Routes ---

@app.post("/keys/upload")
def upload_keys(bundle: PreKeyBundle):
    # 1. Signature Verification (Ed25519)
    # The logic: SignedPreKey must be signed by IdentityKey
    ik_bytes = bytes.fromhex(bundle.identity_key)
    spk_bytes = bytes.fromhex(bundle.signed_pre_key)
    sig_bytes = bytes.fromhex(bundle.signed_pre_key_sig)
    
    try:
        vk = ed25519.Ed25519PublicKey.from_public_bytes(ik_bytes)
        vk.verify(sig_bytes, spk_bytes)
    except Exception as e:
         raise HTTPException(status_code=400, detail=f"Invalid Signature: {str(e)}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # 2. TOFU (Trust On First Use) Check
        cursor.execute("SELECT identity_key FROM users WHERE user_id = ?", (bundle.user_id,))
        existing = cursor.fetchone()
        
        if existing:
            stored_identity = existing[0]
            if stored_identity != bundle.identity_key:
                raise HTTPException(status_code=409, detail="Identity Key Mismatch! Cannot overwrite existing identity.")
        
        # Upsert User (Only update non-identity fields if exists)
        cursor.execute('''
            INSERT INTO users (user_id, identity_key, signed_pre_key, signed_pre_key_sig, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
            signed_pre_key=excluded.signed_pre_key,
            signed_pre_key_sig=excluded.signed_pre_key_sig,
            last_seen=excluded.last_seen
        ''', (bundle.user_id, bundle.identity_key, bundle.signed_pre_key, bundle.signed_pre_key_sig, time.time()))
        
        # Insert One-Time Keys
        for k in bundle.one_time_pre_keys:
            if len(k) == 64: 
                cursor.execute('INSERT INTO one_time_keys (user_id, key_data) VALUES (?, ?)', (bundle.user_id, k))
        
        conn.commit()
    except HTTPException as he:
        conn.rollback()
        raise he
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
        
    return {"status": "ok", "message": f"Keys stored for {bundle.user_id}"}

# --- Message Relay Logic ---
class MessageSend(BaseModel):
    sender_id: str
    recipient_id: str
    content: str # Base64 or Hex encoded ciphertext

MAX_MESSAGES_PER_USER = 100

@app.get("/server/info")
def get_server_info():
    """Returns relay server public key for pinning and protocol versions."""
    return {
        "version": "2.0.0",
        "public_key": "RELAY_IDENTITY_KEY_PROD_REPLACE_ME", # In prod, load from disk
        "supported_algorithms": ["X3DH", "DoubleRatchet", "Ed25519", "X25519"],
        "message_ttl": MESSAGE_TTL
    }

@app.post("/messages/send")
def send_message(msg: MessageSend):
    # Verify sender existence
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Anti-Spam: Check message count for recipient
    cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient_id = ?", (msg.recipient_id,))
    count = cursor.fetchone()[0]
    if count >= MAX_MESSAGES_PER_USER:
        conn.close()
        raise HTTPException(status_code=429, detail="Recipient inbox full. Try again later.")

    # 2. Verify sender existence
    cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (msg.sender_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Sender not found")

    cursor.execute('''
        INSERT INTO messages (recipient_id, sender_id, content, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (msg.recipient_id, msg.sender_id, msg.content, time.time()))
    conn.commit()
    conn.close()
    return {"status": "sent"}

@app.get("/messages/{user_id}")
def get_messages(user_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT sender_id, content, timestamp FROM messages WHERE recipient_id = ? ORDER BY timestamp ASC', (user_id,))
    rows = cursor.fetchall()
    
    messages = []
    for r in rows:
        messages.append({
            "sender_id": r[0],
            "content": r[1],
            "timestamp": r[2]
        })
    
    # Optional: Delete messages after delivery for Forward Secrecy?
    # No, usually we keep until ACKed, but for simplicity we'll delete now
    cursor.execute('DELETE FROM messages WHERE recipient_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return {"messages": messages}

@app.get("/keys/{user_id}", response_model=PreKeyResponse)
def get_key(user_id: str):
    # Validate Input
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', user_id):
        raise HTTPException(status_code=400, detail="Invalid User ID")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT identity_key, signed_pre_key, signed_pre_key_sig FROM users WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
        
    identity_key, signed_pre_key, signed_pre_key_sig = user
    
    # Transactionally fetch and delete one one-time-key
    otp_key = None
    try:
        cursor.execute('SELECT id, key_data FROM one_time_keys WHERE user_id = ? LIMIT 1', (user_id,))
        row = cursor.fetchone()
        if row:
            otp_id, otp_key = row
            cursor.execute('DELETE FROM one_time_keys WHERE id = ?', (otp_id,))
            conn.commit()
    except Exception:
        pass # If we fail to get/delete OTP, just return None, don't crash
    finally:
        conn.close()
    
    return PreKeyResponse(
        identity_key=identity_key,
        signed_pre_key=signed_pre_key,
        signed_pre_key_sig=signed_pre_key_sig,
        one_time_pre_key=otp_key
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
