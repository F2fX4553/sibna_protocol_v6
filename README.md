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

Sibna is a reference messaging kernel written in memory-safe Rust. It handles the complex mathematics of **X3DH** and **Double Ratchet**, providing a production-ready core for secure messaging applications.

### Key Pillars
- 🛡️ **Post-Compromise Security**: Self-healing cryptographic state machine.
- ⚡ **High Performance**: Rust-native core with zero-cost abstractions.
- 📦 **Multi-Language**: Optimized bindings for Python, Flutter, C++, and Web.
- 🔐 **Zero-Knowledge**: Relay servers never touch plaintext or metadata.

---

## 🛠️ Developer Onboarding

If you have just cloned the repository, follow these steps to verify your environment and ensure the kernel is fully functional.

### 1. Build the Core Engine
The core is written in Rust. You must build it first to generate the necessary libraries.
```bash
cd core
cargo build --release
```

### 2. Verify Protocol Integrity (Testing)
Sibna includes a multi-layered test suite to ensure cryptographic correctness.

**Rust Unit Tests:**
Tests the internal state machine and individual primitives.
```bash
cargo test
```

**Full Integration Tests:**
Tests the end-to-end session management using the Python SDK. (Requires Python 3.12+)
```bash
cd tests
python integration_test_full.py
```

---

## 🚀 The SDK Ecosystem

Sibna follows a **Shared Core Architecture**. The engine is built once in Rust and exposed to all other languages via a high-performance FFI (Foreign Function Interface) layer.

### Available SDKs
- **Python**: `pip install bindings/python`
- **Flutter/Dart**: Add `sibna-dart` via Git in `pubspec.yaml`.
- **JavaScript/Web**: `npm install sibna-js`
- **C++**: Integrate using CMake `FetchContent`.

---

## 🏗️ SDK Engineering: Adding New Languages

Developers can create SDKs for any language that supports C-FFI. The process is standardized:

### The "Source of Truth" Model
1.  **Core Kernel**: All cryptographic logic lives in `/core`.
2.  **C-Header Generation**: We use `cbindgen` to create the bridge between Rust and the world.
    ```bash
    cargo install cbindgen
    cbindgen --config core/cbindgen.toml --output core/sibna.h
    ```
3.  **Language Binding**: Create a wrapper in your target language that calls the functions in `sibna.h`.
    - **Per-Language**: You create a specific binding for each language (e.g., Python using PyO3, Dart using `dart:ffi`).
    - **Uniformity**: Every SDK calls the same underlying Rust functions, ensuring identical security behavior across all platforms.

---

## 🧪 Cryptographic Specification

| Primitive | Implementation | Purpose |
| :--- | :--- | :--- |
| **Key Agreement** | X25519 (Curve25519) | Diffie-Hellman |
| **Authentication** | Ed25519 | Identity Signatures |
| **Encryption** | ChaCha20-Poly1305 | AEAD Encryption |
| **KDF** | BLAKE3 / HKDF-SHA256 | Key Derivation |

---

## 📚 Resources

📖 **[Whitepaper](docs/whitepaper.md)** | 🌐 **[Encyclopedia](web/encyclopedia.html)** | 🛠️ **[Dev Guide](DEVELOPER_GUIDE.md)**

---

<p align="center">
  Made with ❤️ for Secure Communication by the <strong>Sibna Core Team</strong>
</p>
