<p align="center">
  <img src="https://i.pinimg.com/736x/d1/f7/d1/d1f7d161f707b20d96d16403c843d82a.jpg" alt="Sibna Hero Banner" width="100%">
</p>

<h1 align="center">Sibna Protocol (v6.1.0)</h1>

<p align="center">
  <strong>Secure E2EE Protocol v6 — High-assurance messaging kernel.</strong>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Language-Rust-orange.svg" alt="Language"></a>
  <img src="https://img.shields.io/badge/Status-Production--Ready-success.svg" alt="Status">
</p>

---

## 💎 The Engineering Behind Absolute Privacy

Sibna is a reference messaging kernel written in memory-safe Rust. It handles the complex mathematics of **X3DH** (Extended Triple Diffie-Hellman) and **Double Ratchet**, providing a production-ready core for secure messaging applications.

### Key Pillars
- 🛡️ **Post-Compromise Security**: Self-healing cryptographic state machine.
- ⚡ **High Performance**: Rust-native core with zero-cost abstractions.
- 📦 **Multi-Language**: Optimized bindings for Python, Flutter, JavaScript, and C++.
- 🔐 **Zero-Knowledge**: Relay servers never touch plaintext or metadata.

---

## 🏗️ Architecture Overview

The Sibna Kernel manages the entire lifecycle of a secure session, from initial handshake to continuous re-keying.

```mermaid
graph TD
    A["User Identity"] --> B{"X3DH Handshake"}
    B -->|"Success"| C["Root Key"]
    C --> D["Double Ratchet"]
    D --> E["Chain Keys"]
    E -->|"Derive"| F["Message Keys"]
    F -->|"Encrypt/Decrypt"| G["Ciphertext"]
    D -->|"Self-Healing"| C
```

---

## 🛡️ Security Architecture

Sibna is built on a **Double Ratchet** core, ensuring that every message increases the security entropy of the session.

- **Self-Healing**: The session recovers automatically from temporary device compromise (Post-Compromise Security).
- **Persistence & OpSec**:
  - **Encrypted Storage**: Local state (keys, sessions, indices) is persisted in a password-derived encryption layer.
  - **Memory Safety**: Sensitive materials are cleared immediately after use via the `zeroize` crate.
- **Forward Secrecy**: Historical messages cannot be decrypted even if current long-term keys are stolen.
- **Zero-knowledge Relay**: The relay server manages opaque blobs and never sees unencrypted content.

---

## 🛠️ Developer Onboarding

### 1. Build the Core Engine
The core is written in Rust. You must build it first to generate the necessary libraries.
```bash
cd core
cargo build --release
```

### 2. Verify Protocol Integrity (Testing)
**Rust Unit Tests:**
```bash
cargo test
```

**Full Integration Tests:** (Requires Python 3.12+)
```bash
cd tests
python integration_test_full.py
```

---

## 🚀 The SDK Ecosystem: Advanced Usage

Sibna follows a **Shared Core Architecture**. Below are professional-grade implementation examples for production environments.

### 🐍 Python SDK: Enterprise Integration
```python
from sibna import SecureContext, Config
# Initialize with persistent encrypted storage
config = Config(storage_path="./vault", db_encryption=True)
ctx = SecureContext(config, password=b"master_secret")

# Asymmetric encryption with automatic ratchet refresh
session = ctx.get_or_create_session(peer_id="alice_99")
ciphertext = session.encrypt(b"Confidential Report")
```

### 💙 Flutter SDK: Mobile-First Security
```dart
import 'package:sibna_dart/sibna_dart.dart';

Future<void> initMessenger() async {
  final ctx = SecureContext(Config(), password: "biometric_key");
  messagingStream.listen((payload) async {
    final plaintext = await ctx.decrypt(payload.senderId, payload.data);
    updateUI(plaintext);
  });
}
```

### ⚡ JavaScript SDK: Web-Worker Isolation
```javascript
import { SibnaKernel } from 'sibna-js';
const kernel = new SibnaKernel();
await kernel.initialize({ engine: 'wasm', masterKey: '...' });
const blob = await kernel.processIncomingMessage(senderId, encryptedBlob);
```

---

## 📂 Repository Layout

| Directory | Content |
| :--- | :--- |
| **`/core`** | Rust-native implementation of the protocol engine. |
| **`/bindings`** | Optimized wrappers for Python and C++. |
| **`/sibna-dart`** | Flutter/Dart SDK for mobile development. |
| **`/sibna-js`** | JavaScript/TypeScript SDK for web apps. |
| **`/docs`** | Whitepaper, API Reference, and Deployment guides. |
| **`/server`** | Reference FastAPI Relay and Pre-Key Server. |

---

## 🏗️ SDK Engineering: Building New Bindings

Developers can extend Sibna to any language. The "One Core, Many Faces" model ensures cryptographic parity.

1.  **Shared Kernel (Rust)**: All logic is in `/core`.
2.  **FFI Bridge**: We export a standard C89-compatible ABI.
3.  **Generating Headers**: `cbindgen --config core/cbindgen.toml --output core/sibna.h`
4.  **Binding Strategy**: Map C pointers to Object-Oriented classes and use destructors to call `sibna_free()` in Rust to prevent memory leaks.

---

## 🧪 Cryptographic Specification

| Primitive | Implementation | Purpose |
| :--- | :--- | :--- |
| **X3DH** | X25519 & Ed25519 | Mutual Authentication & Key Exchange |
| **Ratchet** | HMAC-SHA256 | Symmetrical Key Evolution |
| **AEAD** | ChaCha20-Poly1305 | Authenticated Encryption |
| **Storage** | AES-256-GCM (SIV) | Encrypted Local Persistence |

---

## 📚 Documentation & Resources

- 📖 **[Whitepaper](docs/whitepaper.md)** | 🌐 **[Encyclopedia](web/encyclopedia.html)** | 🛠️ **[Dev Guide](DEVELOPER_GUIDE.md)**
- 🚀 **[Deployment](DEPLOYMENT.md)** | ⚠️ **[Troubleshooting](docs/TROUBLESHOOTING.md)**

---

<p align="center">
  Made with ❤️ for Secure Communication by the <strong>Sibna Core Team</strong>
</p>
