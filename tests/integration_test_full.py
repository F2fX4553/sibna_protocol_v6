import time
import requests
import json
import base64
from sibna import SecureContext, Config

RELAY_URL = "http://localhost:8000"

def test_full_flow():
    print("--- Starting Full Protocol Integration Test ---")
    
    # 1. Setup Clients
    alice_ctx = SecureContext(Config())
    bob_ctx = SecureContext(Config())
    
    # Alice generates identity
    # Note: In a real app, Alice would save/load from storage
    # For test, we use the generated one
    id_a = alice_ctx.get_identity_keypair()
    id_b = bob_ctx.get_identity_keypair()
    
    print(f"Alice ID (Ed25519 Pub): {id_a.ed25519_public.hex()[:10]}...")
    print(f"Bob ID (Ed25519 Pub): {id_b.ed25519_public.hex()[:10]}...")
    
    # 2. Bob Uploads Keys to Relay
    spk_b = bob_ctx.generate_signed_prekey() # This would be a new method or internal
    # For now, let's assume we have a way to get these
    bundle_b = {
        "user_id": "bob",
        "identity_key": id_b.ed25519_public.hex(), # Using Ed25519 for ID
        "signed_pre_key": id_b.x25519_public.hex(), # For now, use identity X25519 as SPK for test
        "signed_pre_key_sig": "0" * 128, # Dummy sig unless we implement signing in python
        "one_time_pre_keys": []
    }
    
    # Note: Real implementation would need real signatures to pass the hardened relay check.
    # I'll update the server to allow 'TEST_MODE' or I'll implement signing in the Python SDK.
    
    print("Step 2: Key Upload skipped (would fail on hardened relay without real signature)")
    
    # 3. Alice fetches Bob's keys
    # res = requests.get(f"{RELAY_URL}/keys/bob")
    # bundle = res.json()
    
    # 4. Handshake & Ratchet
    # alice_ctx.perform_handshake("bob", initiator=True, ...)
    
    print("Integration test framework initialized. Real run requires signing capability in Python.")

if __name__ == "__main__":
    try:
        test_full_flow()
    except Exception as e:
        print(f"Test Failed: {e}")
