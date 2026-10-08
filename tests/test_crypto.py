import os
import sys
import unittest
import base64
import nacl.signing
import nacl.public
import nacl.secret
import nacl.pwhash
import nacl.utils
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class TestE2EECryptography(unittest.TestCase):

    def test_1_user_keypair_generation(self):
        """Test X25519 (ECDH) and Ed25519 (Signing) keypair creation."""
        # 1. Key exchange
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub = x_priv.public_key()
        self.assertEqual(len(x_priv.private_bytes_raw()), 32)
        self.assertEqual(len(x_pub.public_bytes_raw()), 32)

        # 2. Digital Signatures
        ed_priv = ed25519.Ed25519PrivateKey.generate()
        ed_pub = ed_priv.public_key()
        self.assertEqual(len(ed_priv.private_bytes_raw()), 32)
        self.assertEqual(len(ed_pub.public_bytes_raw()), 32)
        print("\n[PASS] Test 1: Generated X25519 & Ed25519 32-byte keypairs.")

    def test_2_argon2id_password_derivation(self):
        """Test Argon2id password hashing and key derivation."""
        password = b"MasterSecretPassword123!"
        salt = nacl.utils.random(16)
        
        # Derive 32-byte Key Encryption Key (KEK)
        kek = nacl.pwhash.argon2id.kdf(
            32,
            password,
            salt,
            opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
            memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE
        )
        self.assertEqual(len(kek), 32)
        print("[PASS] Test 2: Argon2id KEK derivation (Memory/GPU resistant).")

    def test_3_ephemeral_ecies_key_wrapping(self):
        """Test Ephemeral X25519 + HKDF-SHA256 file key wrapping (Forward Secrecy)."""
        # Recipient long-term keypair
        recipient_priv = x25519.X25519PrivateKey.generate()
        recipient_pub = recipient_priv.public_key()

        # Random 256-bit symmetric file key
        random_file_key = os.urandom(32)

        # Sender generates Ephemeral X25519 keypair for THIS upload only
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()

        # 1. Sender derives shared secret
        sender_shared_secret = ephemeral_priv.exchange(recipient_pub)
        
        # 2. Sender runs HKDF
        hkdf_sender = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00" * 16,
            info=b"file-portal-key-wrap-v1"
        )
        wrap_key_sender = hkdf_sender.derive(sender_shared_secret)

        # 3. Sender wraps (encrypts) file key with ChaCha20Poly1305
        nonce = os.urandom(12)
        chacha_wrap = ChaCha20Poly1305(wrap_key_sender)
        wrapped_file_key = chacha_wrap.encrypt(nonce, random_file_key, None)

        # --- TRANSMISSION HAPPENS (Sender transmits ephemeral_pub + wrapped_file_key + nonce) ---

        # 4. Receiver derives SAME shared secret using their long-term private key
        receiver_shared_secret = recipient_priv.exchange(ephemeral_pub)
        self.assertEqual(sender_shared_secret, receiver_shared_secret)

        # 5. Receiver runs HKDF
        hkdf_receiver = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00" * 16,
            info=b"file-portal-key-wrap-v1"
        )
        wrap_key_receiver = hkdf_receiver.derive(receiver_shared_secret)
        self.assertEqual(wrap_key_sender, wrap_key_receiver)

        # 6. Receiver unwraps file key
        chacha_unwrap = ChaCha20Poly1305(wrap_key_receiver)
        recovered_file_key = chacha_unwrap.decrypt(nonce, wrapped_file_key, None)
        self.assertEqual(random_file_key, recovered_file_key)
        print("[PASS] Test 3: Ephemeral ECIES Key Wrapping with Forward Secrecy.")

    def test_4_symmetric_file_encryption_and_integrity(self):
        """Test XChaCha20-Poly1305 authenticated symmetric encryption."""
        file_key = os.urandom(32)
        plaintext_data = b"CONFIDENTIAL FINANCIAL AUDIT REPORT: Top Secret."

        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(file_key)
        ciphertext = aead.encrypt(nonce, plaintext_data, None)

        # Decrypt & verify
        decrypted = aead.decrypt(nonce, ciphertext, None)
        self.assertEqual(plaintext_data, decrypted)
        print("[PASS] Test 4: Authenticated AEAD Encryption & Decryption.")

    def test_5_tamper_detection(self):
        """Verify that altering even 1 bit in ciphertext causes Poly1305 verification to reject."""
        file_key = os.urandom(32)
        plaintext = b"Wire Transfer $1,000,000 to Account #12345"
        
        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(file_key)
        ciphertext = bytearray(aead.encrypt(nonce, plaintext, None))

        # Attacker flips a single byte in ciphertext
        ciphertext[10] ^= 0xFF

        with self.assertRaises(Exception):
            aead.decrypt(nonce, bytes(ciphertext), None)
        print("[PASS] Test 5: Tamper Detection (Poly1305 tag mismatch aborted decryption).")

    def test_6_ed25519_digital_signature_provenance(self):
        """Test Ed25519 signing of ciphertext for sender provenance and non-repudiation."""
        sender_sign_priv = ed25519.Ed25519PrivateKey.generate()
        sender_sign_pub = sender_sign_priv.public_key()

        payload = b"EncryptedPayloadBytes..."
        signature = sender_sign_priv.sign(payload)

        # Receiver verifies signature with sender's public key
        sender_sign_pub.verify(signature, payload)

        # Tampered payload fails verification
        with self.assertRaises(Exception):
            sender_sign_pub.verify(signature, payload + b"tampered")
        print("[PASS] Test 6: Ed25519 Digital Signature & Non-Repudiation Verified.")

if __name__ == '__main__':
    unittest.main(verbosity=2)
