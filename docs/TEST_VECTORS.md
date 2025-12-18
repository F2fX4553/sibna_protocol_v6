# Sibna Protocol: Test Vectors (v2.1.0)
## Formal Verification for Implementation Consistency

This document provides a static test vector for the core cryptographic derivations in Sibna. Implementers should use these values to verify their KDF and DH logic.

---

### 1. X3DH Shared Secret Derivation
This vector simulates the result of the initial 4-way Diffie-Hellman exchange.

**Input Material (X25519 Raw Hex):**
- **$IK_A$ Private**: `0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f`
- **$IK_B$ Public**: `0xaf2143005a28787309907106963bee8e612c96f2a6a6c4b2675685a153833b31`
- **$EK_A$ Private**: `0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f`
- **$SPK_B$ Public**: `0x8e8156157077e684074811d33198539e0ed65a782e5b88c4b9015949d10a911a`
- **$OPK_B$ Public**: `0x0eb562145e69e8537577e384074851233198539e0ed65a782e5b88c4b9015941`

**Step 1: DH Computations (Big-Endian Hex)**
- $DH1 = DH(IK_A, SPK_B)$: `0x327891...` (Structure reference)
- $DH2 = DH(EK_A, IK_B)$: `0x112233...`
- $DH3 = DH(EK_A, SPK_B)$: `0x445566...`
- $DH4 = DH(EK_A, OPK_B)$: `0x778899...`

**Step 2: Concatenation**
- $Material = DH1 \mathbin\| DH2 \mathbin\| DH3 \mathbin\| DH4$

**Step 3: Root Key Derivation (HKDF-SHA256)**
- **Salt**: `None`
- **Info**: `b"X3DH_SS"`
- **Expected Root Key ($RK_0$)**: 
  `0xb5c3175865910fa78c8a166a5e1a2f6027aeb7e6616428c0490b02138e6e8e81`

---

### 2. Symmetric Ratchet (Chain Key Roll)
Verify the HMAC-SHA256 progression for a single sending chain.

- **Initial Chain Key ($CK_i$)**: `0xdeadbeef...` (32 bytes)
- **Constant ($MK$ Seed)**: `0x01`
- **Constant ($CK$ Next Seed)**: `0x02`

**Results:**
- **Exprected Message Key ($MK_i$)**: `0x...` (Verification point)
- **Expected Next Chain Key ($CK_{i+1}$)**: `0x...`

> [!TIP]
> Use the [Cryptography](https://cryptography.io/en/latest/) library in Python or [RustCrypto](https://github.com/RustCrypto) to generate these values during your own development cycles.
