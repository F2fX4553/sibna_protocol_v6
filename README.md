# Sibna Protocol (v6.1.0)
## Secure E2EE Protocol v6 — High-assurance messaging kernel

Sibna is a professional-grade, modular E2EE protocol built in Rust. It implements a self-healing cryptographic state machine designed for asynchronous, zero-trust environments.

---

## 🛠 System Requirements

To build and run Sibna, ensure your environment meets these minimums:

- **Rust**: v1.70+ (Stable)
- **Python**: v3.12+ 
- **C/C++ Build Tools**: 
  - **Linux**: `build-essential`
  - **Windows**: [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (MSVC)
- **Environment**: macOS, Linux, or Windows (WSL recommended for development).

---

## 🚀 Quick Start (Python SDK)

### 1. Installation

#### Windows (Native)
On Windows, you may encounter `os error 32` (File Locking) due to Antivirus or active processes. 
- **Tip**: Disable real-time protection during `cargo build` or use a workspace directory excluded from scanning.
- **Tip**: Ensure `cbindgen` is installed via `cargo install --force cbindgen`.

```powershell
# Clone and build the core
git clone https://github.com/sibna/protocol-v2.git
cd protocol-v2/core
cargo build --release

# Link or install the Python SDK
cd ../bindings/python
pip install -e .
```

### 2. Implementation
```python
from sibna import SecureContext, Config

# Initialize context with persistence
ctx = SecureContext(Config(), password=b"master_key")

# Establish a session (X3DH)
# session = ctx.perform_handshake(...) 

# Encrypt and Decrypt
ciphertext = ctx.encrypt_message(peer_id, b"Absolute Technical Truth")
plaintext = ctx.decrypt_message(peer_id, ciphertext)
```

---

## 🛡 Security Architecture

Sibna is built on a **Double Ratchet** core, ensuring that every message increases the security entropy of the session.

- **Self-Healing**: The session recovers automatically from temporary device compromise (Post-Compromise Security).
- **Persistence & OpSec**
  - **Encrypted Storage**: Local state (keys, sessions, indices) is persisted in a password-derived encryption layer backed by `sled`.
  - **Memory Safety**: Sensitive materials are cleared immediately after use via the `zeroize` crate.
- **Forward Secrecy**: Historical messages cannot be decrypted even if current long-term keys are stolen.
- **Zero-knowledge Relay**: The relay server manages opaques blobs and never sees unencrypted content or metadata beyond routing IDs.

### Cryptographic Specification
- **X25519**: Curve25519 for Diffie-Hellman Key Agreement.
- **ChaCha20-Poly1305**: IETF AEAD for authenticated encryption.
- **HMAC-SHA256**: Symmetric chaining and key derivation.
- **Ed25519**: Identity and Pre-Key signatures.

---

## 📂 Repository Layout

| Directory | Content |
| :--- | :--- |
| **`/core`** | Rust-native implementation of the protocol engine. |
| **`/server`** | Reference FastAPI Relay and Pre-Key Server. |
| **`/bindings`** | Optimized wrappers for Python and C++. |
| **`/docs`** | [Whitepaper](docs/whitepaper.md), [API Reference](docs/API_REFERENCE.md), [Deployment](docs/DEPLOYMENT.md). |
| **`/examples`** | [CLI Messenger](examples/cli_messenger.py), [File Vault](examples/file_vault.py). |

---

## 📜 Documentation Suite

For deeper integration and theoretical understanding, please refer to:
- **[Technical Whitepaper](docs/whitepaper.md)**: Cryptographic proofs and byte-level specifications.
- **[API Reference](docs/API_REFERENCE.md)**: Full SDK method documentation.
- **[Deployment Guide](docs/DEPLOYMENT.md)**: Scaling and securing the Relay server.
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)**: Common build and runtime fixes.
- **[Contributing Guide](docs/CONTRIBUTING.md)**: How to help improve Sibna.

---

## ⚖️ License
Licensed under **Apache-2.0** or **MIT**.

---
**Made with ❤️ for Secure Communication**
