"""Public RFC vectors and frozen reference output; no crypto package required."""
import ast
import json
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

import node


class StandardLibraryCryptoTests(unittest.TestCase):
    def test_rfc8439_chacha20_block(self):
        # RFC 8439 section 2.3.2 (public test inputs, not deployment keys).
        expected = bytes.fromhex(
            '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e'
            'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e')
        result = node._chacha_block(bytes(range(32)), 1, bytes.fromhex('000000090000004a00000000'))
        self.assertEqual(result, expected)

    def test_rfc8439_poly1305(self):
        # RFC 8439 section 2.5.2.
        vector_key = bytes.fromhex('85d6be7857556d337f4452fe42d506a8'
                                   '0103808afb0db2fd4abff6af4149f51b')
        self.assertEqual(node._poly1305(vector_key, b'Cryptographic Forum Research Group'),
                         bytes.fromhex('a8061dc1305136c6c22b8baf0c0127a9'))

    def test_rfc7748_x25519(self):
        # RFC 7748 section 6.1: published Alice/Bob values.
        alice = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        bob = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        alice_public = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        bob_public = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
        base = b'\x09' + bytes(31)
        self.assertEqual(node._x25519(alice, base), alice_public)
        self.assertEqual(node._x25519(bob, base), bob_public)
        shared = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
        self.assertEqual(node._x25519(alice, bob_public), shared)
        self.assertEqual(node._x25519(bob, alice_public), shared)
        with self.assertRaises(ValueError):
            node._x25519(alice, bytes(32))

    def test_frozen_independent_noise_vectors(self):
        # Produced by noiseprotocol 0.3.1, never needed to run these tests.
        # Public inputs: PSK=00..1f, ephemeral initiator=20..3f, responder=40..5f.
        vectors = json.loads((Path(__file__).parent / 'test_vectors/noise_nnpsk0.json').read_text())
        left = node._Noise(bytes(range(32)), True, ephemeral=bytes(range(32, 64)))
        right = node._Noise(bytes(range(32)), False, ephemeral=bytes(range(64, 96)))
        first = left.write_message()
        self.assertEqual(first.hex(), vectors['first'])
        self.assertEqual(right.read_message(first), b'')
        second = right.write_message()
        self.assertEqual(second.hex(), vectors['second'])
        self.assertEqual(left.read_message(second), b'')
        self.assertEqual(left.h.hex(), vectors['hash'])
        self.assertEqual(right.h, left.h)
        for row in vectors['transport']:
            plain = bytes.fromhex(row['plain'])
            encrypted = left.encrypt(plain)
            self.assertEqual(encrypted.hex(), row['i_to_r'])
            self.assertEqual(right.decrypt(encrypted), plain)
            encrypted = right.encrypt(plain)
            self.assertEqual(encrypted.hex(), row['r_to_i'])
            self.assertEqual(left.decrypt(encrypted), plain)

    def test_authentication_failure_and_nonce_exhaustion(self):
        key = secrets.token_bytes(32)
        sender, receiver = node._Cipher(key), node._Cipher(key)
        encrypted = sender.encrypt(b'context', b'payload')
        with self.assertRaises(ValueError):
            receiver.decrypt(b'wrong context', encrypted)
        self.assertEqual(receiver.nonce, 0)
        with self.assertRaises(ValueError):
            receiver.decrypt(b'context', encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
        self.assertEqual(receiver.decrypt(b'context', encrypted), b'payload')
        with self.assertRaises(ValueError):
            receiver.decrypt(b'context', encrypted)
        sender.nonce = 2**64 - 1
        with self.assertRaises(ValueError):
            sender.encrypt(b'', b'')

    def test_aead_padding_matches_frozen_independent_reference(self):
        vectors = json.loads((Path(__file__).parent / 'test_vectors/noise_nnpsk0.json').read_text())
        cipher = node._Cipher(bytes(range(32)))
        cipher.nonce = 7
        encrypted = cipher.encrypt(bytes(range(17)), bytes(range(129)))
        self.assertEqual(encrypted.hex(), vectors['aead_reference'])
        cipher = node._Cipher(bytes(range(32)))
        cipher.nonce = 7
        self.assertEqual(cipher.decrypt(bytes(range(17)), encrypted), bytes(range(129)))

    def test_node_uses_only_standard_library_and_has_no_installer(self):
        source = Path(node.__file__).read_text()
        tree = ast.parse(source)
        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                modules = [alias.name.split('.')[0] for alias in item.names]
            elif isinstance(item, ast.ImportFrom):
                modules = [(item.module or '').split('.')[0]]
            else:
                continue
            self.assertTrue(all(name in sys.stdlib_module_names for name in modules), modules)
        self.assertNotIn('ensure_noise_dependency', source)
        self.assertNotIn('subprocess', source)
        result = subprocess.run([sys.executable, '-S', node.__file__, '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('--ca-file', result.stdout)
        self.assertNotIn('--allow-insecure-ws', result.stdout)


if __name__ == '__main__':
    unittest.main()
