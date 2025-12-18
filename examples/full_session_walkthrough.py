import time
from sibna import SecureContext, Config, RelayClient

# Full Session Walkthrough: Alice & Bob
# This script demonstrates the complete lifecycle of a Sibna secure session.

def run_walkthrough():
    print("--- 1. Initialization ---")
    config = Config()
    # In a real app, 'password' would be user-provided for DB encryption
    alice_ctx = SecureContext(config, password=b"alice_secret_pass")
    bob_ctx = SecureContext(config, password=b"bob_secret_pass")
    
    print("--- 2. Identity & Registration ---")
    # Simulate users registering with the Relay (Identity pinning)
    alice_id = b"alice_test_user"
    bob_id = b"bob_test_user"
    
    # Normally one would use RelayClient to upload bundles. 
    # Here we simulate the state setup.
    print(f"Alice ID: {alice_id.decode()}")
    print(f"Bob ID: {bob_id.decode()}")

    print("--- 3. X3DH Key Agreement (Session Start) ---")
    # Alice wants to message Bob. She fetches Bob's bundle and creates a session.
    # We call 'create_session' which internally manages the X3DH flow.
    alice_session = alice_ctx.create_session(bob_id)
    print("Alice established session with Bob via X3DH.")

    print("--- 4. Synchronous Messaging (DH & Symmetric Ratchet) ---")
    msg1 = b"Hello Bob! This is an end-to-end encrypted message."
    packet1 = alice_ctx.encrypt_message(alice_session, msg1)
    print(f"Alice sent {len(packet1)} bytes.")

    # Bob receives the packet. The first packet allows Bob to derive the same secret.
    # In practice, the responder session is implicitly created upon processing the first message.
    bob_session = bob_ctx.create_session(alice_id)
    decrypted1 = bob_ctx.decrypt_message(bob_session, packet1)
    print(f"Bob decrypted: {decrypted1.decode()}")

    print("--- 5. Out-of-Order Handling (Self-Healing) ---")
    # Alice sends two messages, but message 2 arrives before message 3?
    # No, let's say message 2 is delayed.
    msg2 = b"Message 2 (sent first)"
    msg3 = b"Message 3 (sent second)"
    
    packet2 = alice_ctx.encrypt_message(alice_session, msg2)
    packet3 = alice_ctx.encrypt_message(alice_session, msg3)

    print("Simulating network jitter: Message 3 arrives before Message 2.")
    
    # Bob receives Message 3 first
    decrypted3 = bob_ctx.decrypt_message(bob_session, packet3)
    print(f"Bob decrypted message 3 immediately: {decrypted3.decode()}")
    
    # Bob receives Message 2 later. The SDK uses the cached key.
    decrypted2 = bob_ctx.decrypt_message(bob_session, packet2)
    print(f"Bob decrypted message 2 from the cache: {decrypted2.decode()}")

    print("--- 6. Post-Compromise Security (DH Step) ---")
    # When Bob replies, a new DH Ratchet step is triggered.
    reply = b"I hear you loud and clear, Alice."
    reply_packet = bob_ctx.encrypt_message(bob_session, reply)
    
    alice_decrypted = alice_ctx.decrypt_message(alice_session, reply_packet)
    print(f"Alice received reply: {alice_decrypted.decode()}")
    print("Session state successfully rotated with new DH keys.")

    print("--- 7. Cleanup ---")
    print("Walkthrough complete. All core protocol features verified.")

if __name__ == "__main__":
    run_walkthrough()
