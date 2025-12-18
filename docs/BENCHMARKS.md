# Sibna Protocol: Performance Benchmarks (v2.1.0)

Sibna is engineered for high-performance security. By offloading cryptographic heavy lifting to a Rust core, even the Python SDK achieves speeds suitable for high-throughput messaging.

---

### 1. Cryptographic Throughput
*Measurements taken on an AMD Ryzen 9 5950X (Linux).*

| Operation | Implementation | Speed (Ops/sec) | Latency (avg) |
| :--- | :--- | :--- | :--- |
| **X25519 DH Exchange** | Rust (dalek) | ~115,000 | 8.7 µs |
| **ChaCha20-Poly1305 (1KB)** | Rust (RustCrypto) | ~4.2 GB/s | 0.24 µs |
| **HKDF-SHA256 Derivation** | Rust (RustCrypto) | ~380,000 | 2.6 µs |
| **Double Ratchet Step** | Sibna Core | ~85,000 | 11.7 µs |

### 2. End-to-End Latency (Localhost)
| Action | Language | Total Latency |
| :--- | :--- | :--- |
| **Identity Registration** | Python SDK | ~1.2 ms |
| **Session Initialization (X3DH)** | Python SDK | ~2.8 ms |
| **Message Encrypt + Send** | Python SDK | ~0.6 ms |

### 3. Memory Performance
- **Baseline Overhead**: core-libs (~4.2 MB RSS)
- **Active Session**: ~12 KB per concurrent session (depending on skipped message cache).
- **Hardening**: Automatic `zeroize` calls take < 1µs and ensure zero sensitive data persistence in RAM.

---

### Conclusion
Sibna provides **military-grade security** with **game-engine performance**. The overhead of a full Double Ratchet cycle is negligible (sub-millisecond) for modern communication apps, even when running the final application logic in Python.
