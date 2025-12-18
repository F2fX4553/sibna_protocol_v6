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
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</p>

---

## 💎 The Engineering Behind Absolute Privacy

Sibna is a reference messaging kernel written in memory-safe Rust. It handles the complex mathematics of **X3DH** and **Double Ratchet**, providing a production-ready core for secure messaging applications.

### Key Pillars
- 🛡️ **Post-Compromise Security**: Self-healing cryptographic state machine.
- ⚡ **High Performance**: Rust-native core with zero-cost abstractions.
- 📦 **Multi-Language**: Optimized bindings for Python, C++, and Flutter/Dart.
- 🔐 **Zero-Knowledge**: Relay servers never touch plaintext or metadata.

---

## 🏗️ Architecture Overview

The Sibna Kernel manages the entire lifecycle of a secure session, from initial handshake to continuous re-keying.

```mermaid
graph TD
    A[User Identity] --> B{X3DH Handshake}
    B -->|Success| C[Root Key]
    C --> D[Double Ratchet]
    D --> E[Chain Keys]
    E --> F[Message Keys]
    F -->|Encrypt/Decrypt| G[Ciphertext]
    D -->|Self-Healing| C
```

---

## 🚀 Quick Start

### 🐍 Python SDK

```bash
# Install from source
git clone https://github.com/F2fX4553/sibna_protocol_v6.git
cd sibna_protocol_v6/bindings/python
pip install .
```

### 💙 Flutter / Dart SDK

Add the dependency to your `pubspec.yaml`:

```yaml
dependencies:
  sibna_dart:
    git:
      url: https://github.com/F2fX4553/sibna_protocol_v6.git
      path: sibna-dart
```

### Basic Usage (Dart)

```dart
import 'package:sibna_dart/sibna_dart.dart';

// Initialize context
final ctx = SecureContext(Config(), password: "master_key");

// Encrypt a secret
final ciphertext = await ctx.encryptMessage("peer_id", "High-Assurance Truth");
```

---

## 🧪 Cryptographic Specification

| Primitive | Implementation | Purpose |
| :--- | :--- | :--- |
| **Key Agreement** | X25519 (Curve25519) | Diffie-Hellman Exchange |
| **Authentication** | Ed25519 | Identity Signatures |
| **Encryption** | ChaCha20-Poly1305 | AEAD Authenticated Data |
| **Hashing** | HMAC-SHA256 / BLAKE3 | KDF & Chain Management |

---

## 📚 Resources

- 📖 **[Technical Whitepaper](docs/whitepaper.md)**: Cryptographic proofs and specifications.
- 🛠️ **[Developer Guide](DEVELOPER_GUIDE.md)**: Building and contributing.
- 🌐 **[Encyclopedia](web/encyclopedia.html)**: Deep-dive into protocol internals.
- 🚀 **[Deployment](DEPLOYMENT.md)**: Scaling the Relay server.

---

<p align="center">
  Made with ❤️ for Secure Communication<br>
  <strong>Sibna Core Team</strong>
</p>
