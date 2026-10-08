# 🔒 End-to-End Secure File Exchange Portal using Hybrid Cryptography

An enterprise-grade, academically defensible **End-to-End Encrypted (E2EE)** file exchange portal combining **XChaCha20-Poly1305**, **X25519**, **Ed25519**, **HKDF**, and **Argon2id** with a **Python Flask** backend and **MongoDB**.

---

## 🌟 Key Features

1. **True Client-Side End-to-End Encryption (E2EE):**
   * Encryption and decryption occur **100% inside the user's browser**.
   * The server and database only ever store ciphertext blobs—even a full server breach exposes zero plaintext data.
2. **Hybrid Cryptographic Architecture:**
   * **Symmetric File Encryption:** 256-bit AEAD (**XChaCha20-Poly1305**) with a 192-bit nonce preventing key/nonce collision.
   * **Key Exchange & Forward Secrecy:** **Ephemeral X25519** ECDH key agreement with **HKDF-SHA256** key derivation.
   * **Non-Repudiation & Provenance:** **Ed25519** digital signatures guaranteeing sender identity and file integrity.
   * **Client Key Protection:** **Argon2id / PBKDF2** password-derived Key Encryption Key (KEK) protecting private keys in RAM.
3. **Zero-Knowledge Link Sharing:**
   * Support for URL fragment `#key=...` links where the decryption key is contained in the hash fragment (which is never sent across HTTP to the server).
4. **Access Control & Lifecycle Management:**
   * Time-based expiration timers (e.g. 1 hour, 24 hours, 7 days).
   * Download counter limits (e.g. self-destruct after 1 download).
5. **Interactive Cryptographic Inspector:**
   * Real-time UI dashboard visualizing the cryptographic pipeline at each step.

---

## 📁 Directory Structure

```text
fileexchange/
├── backend/
│   ├── app.py                # Main Flask application & route handlers
│   ├── models.py             # Database layer (MongoDB + Local JSON fallback)
│   ├── auth.py               # JWT authentication & bcrypt password hashing
│   ├── crypto_helpers.py     # Backend cryptographic validators
│   ├── config.py             # System configuration
│   └── requirements.txt      # Python dependencies
├── frontend/
│   ├── index.html            # Main Portal SPA
│   ├── download.html         # Receiver Decryption & Download Portal
│   ├── js/
│   │   ├── crypto_engine.js  # Client-side WebCrypto / Libsodium engine
│   │   ├── api.js            # API communication client
│   │   └── app.js            # UI logic and event controller
│   └── css/
│       └── style.css         # Dark-themed cybersecurity styling
├── tests/
│   ├── test_crypto.py        # Automated crypto primitive & tamper test suite
│   └── test_api.py           # Automated API & access limit test suite
├── uploads/                  # Encrypted ciphertext storage directory
├── run_server.py             # Entrypoint launcher script
└── README.md
```

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Run Automated Test Suites
Verify all cryptographic primitives, forward secrecy, and tamper detection:
```bash
python tests/test_crypto.py
python tests/test_api.py
```

### 3. Start the Portal
```bash
python run_server.py
```
Open your browser at **`http://127.0.0.1:5000`**.

---

## 🎓 Viva / Review Defense Guide

* **Q: Why XChaCha20-Poly1305 instead of standard AES-GCM?**
  * *Answer:* Standard AES-GCM uses a 96-bit nonce. Under random nonce generation, collision risks emerge after $2^{32}$ messages. XChaCha20 uses a **192-bit nonce**, completely eliminating nonce-reuse risks. It also offers consistent speed across devices without dedicated AES hardware.
* **Q: How does Forward Secrecy work in this project?**
  * *Answer:* For each upload, the sender generates a brand new ephemeral X25519 keypair. Even if the sender's long-term key is compromised in the future, past shared files cannot be decrypted because the ephemeral private key was erased from RAM immediately after upload.
* **Q: What is the purpose of HKDF?**
  * *Answer:* Raw Diffie-Hellman secrets are points on an elliptic curve and are not uniformly random. HKDF (RFC 5869) extracts entropy and expands it into a cryptographically uniform 256-bit symmetric key.
