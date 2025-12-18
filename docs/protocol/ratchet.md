# Double Ratchet Implementation

The Sibna Protocol implements a robust Double Ratchet algorithm as described by Trevor Perrin and Moxie Marlinspike.

## Core Components

### 1. Diffie-Hellman Ratchet
Every exchange of messages (round-trip) triggers a new X25519 DH exchange. This rotates the **Root Key**, providing **Post-Compromise Security**. If an attacker gains access to the ephemeral keys at time *T*, they are locked out as soon as a new DH ratchet step occurs.

### 2. Symmetric-Key Ratchet
Each DH ratchet step seeds two symmetric chains:
- **Sending Chain**: For outgoing messages.
- **Receiving Chain**: For incoming messages.

Within these chains, keys roll forward using HKDF-SHA256. This provides **Forward Secrecy**: once a message is decrypted or sent, its unique key and the intermediate chain key are deleted.

## Out-of-Order Message Handling
Sibna manages out-of-order messages by caching "skipped" message keys.
- **Max Skip Limit**: Configured via `max_skipped_messages` (default: 2000).
- **Expiration**: Skipped keys are deleted after a certain number of ratchet steps to prevent memory exhaustion attacks.

## Header Encryption
To protect metadata, the message header is encrypted using a separate header key. This prevents an eavesdropper from determining the sequence number of messages unless they have the session's header secret.
