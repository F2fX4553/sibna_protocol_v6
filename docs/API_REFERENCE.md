# Sibna SDK: API Reference (Python)
## Comprehensive Guide to the `sibna` SDK

### 1. `SecureContext`
The primary entry point for the protocol. It manages the keystore, sessions, and persistence.

#### `__init__(config: Config = None, password: bytes = None)`
Initializes a new context.
- `config`: An instance of `Config`.
- `password`: Required for decrypting the local persistence store (`sled`).

#### `load_identity(ed_pub: bytes, x_pub: bytes, seed: bytes)`
Loads a pre-existing identity into the local store.
- `ed_pub`: 32-byte Ed25519 public key.
- `x_pub`: 32-byte X25519 public key.
- `seed`: 32-byte identity seed.

#### `create_session(peer_id: bytes) -> SessionHandle`
Creates or loads a session for a specific peer ID.

#### `encrypt_message(session_id: bytes, plaintext: bytes) -> bytes`
Encrypts a payload using the currently active ratchet chain. Returns the full binary packet (including header).

#### `decrypt_message(session_id: bytes, ciphertext: bytes) -> bytes`
Decrypts a packet and advances the ratchet state. Handles out-of-order and skipped messages.

---

### 2. `Config`
Configure protocol-level behavior and limits.

#### `__init__(...)`
Parameters (with defaults):
- `enable_forward_secrecy`: `True`
- `enable_post_compromise_security`: `True`
- `max_skipped_messages`: `1000` (Max keys to cache for out-of-order delivery)
- `key_rotation_interval`: `3600` (Seconds)

---

### 3. `RelayClient`
A high-level utility for communicating with the reference Sibna Relay Server.

#### `connect(host: str, port: int)`
Establishes a connection and registers the user's identity.

#### `send_message(recipient_id: bytes, data: bytes)`
Sends an opaque blob to the target recipient.

#### `fetch_messages() -> List[tuple]`
Polls the relay server for pending envelopes.

---

### 4. Error Handling
The SDK raises `RuntimeError` for protocol violations (e.g., integrity check failure, session expired). Always wrap crypto operations in a `try-except` block.
