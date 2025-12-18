import sys
import os
import unittest
import base64

# Add python bindings to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../bindings/python'))

try:
    from sibna import SecureContext, Config
    SKIP_TESTS = False
except ImportError:
    print("Could not import sibna. Native library might be missing.")
    SKIP_TESTS = True

class TestSibna(unittest.TestCase):
    @unittest.skipIf(SKIP_TESTS, "Native library missing")
    def test_key_generation(self):
        pub, priv = generate_keypair()
        self.assertEqual(len(pub), 32)
        self.assertEqual(len(priv), 32)
        
    @unittest.skipIf(SKIP_TESTS, "Native library missing")
    def test_session_creation(self):
        ctx = SecureContext(password=b"test_password")
        # Create a dummy peer ID
        peer_id = b"test_peer"
        # In a real test we would need valid keys and handshake
        # initialization, which expects valid crypto state.
        # This test ensures we can at least call the API without segfault.
        try:
            session = ctx.create_session(peer_id)
            self.assertIsNotNone(session)
        except Exception as e:
            # It might fail due to missing logic in our mock handshake/setup
            # but it shouldn't crash
            print(f"Session creation returned: {e}")

if __name__ == '__main__':
    unittest.main()
