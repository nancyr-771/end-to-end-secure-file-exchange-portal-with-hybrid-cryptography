# 🔒 SecureFileExchange: End-to-End Secure File Exchange Portal Using Modern Hybrid Cryptography

**Project Location:** `C:\Users\EBIN\Downloads\fileexchange`  
**Version:** `3.2.0 (Production Release)`  
**Architecture:** Python Flask REST API + MongoDB / Dual Persistent Layer + Modern Responsive Web Interface + Hybrid Cryptography  

---

## 1. Executive Summary & Project Aim

### 🎯 Aim
To design, implement, and deploy a secure, modern web-based file exchange portal that ensures maximum confidentiality, integrity, sender authenticity, and controlled access for sensitive data transfers. The application replaces obsolete cryptographic primitives (such as legacy AES-CBC and RSA-2048) with high-speed, modern algorithms: **XChaCha20-Poly1305 (256-bit AEAD)**, **X25519 (ECDH)**, **HKDF-SHA256**, **Ed25519 Digital Signatures**, and **Argon2id / PBKDF2**.

---

## 2. Problem Statement & Motivation

### ❌ The Vulnerabilities of Traditional File Sharing Systems:
1. **Server-Side Decryption Risks:** Conventional cloud storage providers hold encryption keys on their servers, leaving stored documents vulnerable to database breaches, rogue insiders, and unauthorized subpoena extraction.
2. **Obsolete Cryptographic Standards in Legacy Projects:**
   * **RSA-2048 / RSA-4096:** Computationally intensive, massive key sizes (512 bytes), and prone to cache-timing side-channel attacks.
   * **AES-CBC:** Prone to padding oracle attacks (e.g., POODLE, Lucky 13).
   * **AES-GCM Nonce Collisions:** Employs a 96-bit nonce; randomly generating nonces risks catastrophic key-recovery collision after approximately $2^{32}$ files (Birthday Paradox).
   * **Weak Password Hashing (MD5, SHA-256):** Lacks memory hardness, allowing GPU and ASIC cracking rigs to test billions of combinations per second.
3. **Uncontrolled File Life Cycles:** Links remain accessible indefinitely without automated expiration or download limits.
4. **Multi-Tenant Information Leakage:** Shared access logs often expose interactions and metadata across unrelated user accounts.

---

## 3. Objectives

* **Modern Hybrid Cryptography:** Employ authenticated encryption (**XChaCha20-Poly1305**), elliptic-curve key agreement (**X25519**), key derivation (**HKDF-SHA256**), and digital signatures (**Ed25519**).
* **Controlled Sharing & Self-Destruction:** Enable configurable time-to-live (TTL) expiration (1h, 24h, 3d, 7d) and strict download limits ($N$ maximum downloads).
* **Constant-Time Tamper Resistance:** Ensure that any modification to ciphertext or headers immediately aborts decryption via Poly1305 MAC tag validation.
* **Non-Repudiation & Sender Verification:** Sign encrypted file payloads with the sender's Ed25519 private key so recipients can cryptographically verify provenance.
* **Privacy-Preserving User Isolation:** Provide a user-scoped security audit trail that records personal actions without leaking other users' data.
* **Clean, Professional 7-Page Architecture:** Deliver a streamlined user experience modeled after industry-leading security tools (such as Bitwarden Send and Proton Drive).

---

## 4. Cryptographic Suite & Technology Stack

```
+------------------------------------+---------------------------------------------------------------+
| Component                          | Algorithm / Standard                                         |
+------------------------------------+---------------------------------------------------------------+
| Symmetric File Encryption          | XChaCha20-Poly1305 AEAD (256-bit Key, 192-bit Nonce in RAM)   |
| Key Agreement / Forward Secrecy    | Ephemeral X25519 (ECDH over Curve25519, RFC 7748)             |
| Key Derivation Function (KDF)      | HKDF-SHA256 (RFC 5869)                                        |
| Digital Signatures                 | Ed25519 (Edwards-curve Digital Signatures, RFC 8032)          |
| Client RAM Key Vault Derivation    | PBKDF2 (100,000 Rounds, SHA-256)                              |
| Server Account Password Hashing    | Bcrypt (12 Salt Rounds)                                       |
| API Authentication                 | Stateless JWT Tokens (HS256)                                  |
| Transport Security                 | TLS 1.3 / HTTPS                                               |
| Web Backend Framework              | Python 3.13 + Flask 3.1 REST API (Ciphertext Storage Only)    |
| Database Layer                     | MongoDB 8.0 (with transparent zero-setup JSON fallback)      |
| Frontend Client-Side Crypto Core   | WebCrypto API / Vanilla ES6+ JavaScript (`crypto_engine.js`)  |
+------------------------------------+---------------------------------------------------------------+
```

### Why These Algorithms Were Chosen:

1. **XChaCha20-Poly1305 vs. AES-GCM:**  
   XChaCha20 extends the nonce size from 96 bits to **192 bits**. This makes nonce collisions mathematically impossible when generating random nonces for millions of files, avoiding the key-recovery flaw of AES-GCM.
2. **X25519 vs. RSA-2048:**  
   X25519 uses compact 32-byte public keys, executes in constant time (immune to timing attacks), and provides 128-bit security at a fraction of RSA's CPU overhead.
3. **Ed25519 vs. ECDSA:**  
   Ed25519 avoids the need for a unique, perfectly random nonce during signing (which famously broke Sony PS3's ECDSA implementation) and offers fast signature verification.
4. **Argon2id vs. Standard Hashes:**  
   Argon2id is the winner of the Password Hashing Competition (RFC 9106); its memory-hard design requires substantial RAM, rendering GPU-based password cracking inefficient.

---

## 5. Application Architecture & 7 Core Pages

```text
SecureFileExchange Application
│
├── 🔐 Authentication (Login / Register Modal with Argon2id)
│
├── 📄 Page 1: Dashboard
│   ├── Personalized Greeting ("Good evening, [Name]")
│   ├── 4 Stat Cards: [My Files] [Shared With Others] [Received Files] [Expiring Soon]
│   ├── Recent Files Activity List
│   └── Quick Actions: [Upload File] [View Shared Links] [Check Received]
│
├── 📤 Page 2: Upload File
│   ├── Drag-and-Drop Uploader (with auto format detection)
│   ├── Cryptographic Indicators: XChaCha20-Poly1305 ✓ | X25519 ✓ | Poly1305 Integrity ✓
│   ├── Expiration Timers (1h, 24h, 3d, 7d) & Max Download Limits
│   ├── Optional Out-of-Band Secret Passphrase Protection
│   └── Visual Progress Stepper (Reading → KeyGen → Encrypting → Upload Complete)
│
├── 📁 Page 3: My Files
│   ├── Searchable File Inventory (Search by filename)
│   ├── Status Badges ("Encrypted") & Upload Timestamps
│   └── Action Button (⋮ Details) opening File Details Modal
│
├── 🔗 Page 4: Shared Files
│   ├── List of active outbound transfers
│   ├── Recipient information, Expiry countdown, and Download counts (e.g. 3 / 5)
│   └── 1-Click [Copy Secure Link]
│
├── 📥 Page 5: Received Files
│   ├── Live badge counter of incoming files
│   ├── Sender provenance details
│   └── 1-Click [🔓 Decrypt] button with In-Browser Live Preview
│
├── 📜 Page 6: Security Activity Log
│   ├── Privacy-preserving user audit trail
│   └── Event tracking: User Registered, Login Success, File Uploaded, File Downloaded, Expired Access Attempt, File Deleted
│
├── 🛡️ Page 7: Security Overview
│   ├── Live status of all 6 cryptographic primitives (All Enabled ✓)
│   └── Clear, professional viva explanations ("Why is my file secure?")
│
├── ⚙️ Page 8: Settings
│   ├── Profile info (Name, Email)
│   ├── Sharing defaults (Default Expiry, Default Max Downloads)
│   └── Danger Zone (Account Deletion)
│
└── 📋 Modal Component: File Details Modal
    ├── Filename, Size, Status: Encrypted
    ├── Active Ciphers: XChaCha20-Poly1305, X25519, Ed25519 ✓
    ├── Created Date, Expiration Date, Download Limits
    └── [Copy Link] and [Delete File] action buttons
```

---

## 6. End-to-End System Workflow

### Step 1: Account Registration & Identity Keypair Generation
1. User registers with Name, Email, and Master Password.
2. The system generates dual 256-bit keypairs:
   * **Key Exchange:** X25519 public/private key.
   * **Digital Signing:** Ed25519 public/private key.
3. The master password derives a Key Encryption Key (KEK) via **Argon2id / PBKDF2 (100,000 rounds)**.
4. Private keys are encrypted into an `encrypted_key_vault`.
5. Public keys and the encrypted vault are saved to MongoDB; plaintext private keys are never stored on the server.

### Step 2: File Encryption & Upload
1. Sender selects a file via drag-and-drop.
2. The system generates a fresh, random 256-bit symmetric **File Key** ($K_{file}$).
3. File bytes are encrypted using **XChaCha20-Poly1305 AEAD**.
4. **Forward Secrecy Key Wrapping:**
   * An ephemeral X25519 keypair is generated.
   * A shared secret is computed: $S = \text{ECDH}(ephem_{priv}, PK_{recipient})$.
   * HKDF-SHA256 derives a wrapping key: $K_{wrap} = \text{HKDF}(S)$.
   * The File Key is wrapped: $WrappedKey = \text{Encrypt}_{K_{wrap}}(K_{file})$.
5. **Digital Signature:** The ciphertext is signed with the sender's **Ed25519 Private Key**.
6. The ciphertext blob, wrapped key, ephemeral public key, signature, expiry, and download limits are saved to the backend.

### Step 3: Link Distribution & Access Control
1. A unique UUID share link is created: `http://127.0.0.1:5000/download/<UUID>`.
2. Senders can copy and distribute this link via email, messaging, or Slack.

### Step 4: Verification, Decryption & Live Preview
1. Recipient opens the link. The backend verifies that `current_time < expires_at` and `download_count < max_downloads`.
2. The recipient recovers $K_{file}$ by computing $\text{ECDH}(SK_{recipient}, ephem_{pub})$ and running HKDF.
3. The sender’s **Ed25519 signature** is verified against the ciphertext to confirm sender authenticity.
4. The **Poly1305 AEAD tag** is verified; if any byte is altered, decryption immediately aborts.
5. The decrypted file is displayed in a live in-browser preview (images, text, documents) or downloaded directly.

### Step 5: File Expiration & Deletion
* When a file reaches its maximum download limit or expires, access is blocked and logged.
* Manual deletion permanently removes the encrypted object and invalidates the share link.

---

## 7. Verification & Automated Test Results

The project includes an automated test suite covering cryptographic primitives and API endpoints:

```text
======================================================================
TEST SUITE: Cryptographic Primitives (tests/test_crypto.py)
======================================================================
test_1_user_keypair_generation .................................... [PASS]
  -> Generated X25519 & Ed25519 32-byte keypairs.
test_2_argon2id_password_derivation ............................... [PASS]
  -> Argon2id KEK derivation (Memory/GPU resistant).
test_3_ephemeral_ecies_key_wrapping ............................... [PASS]
  -> Ephemeral ECIES Key Wrapping with Forward Secrecy.
test_4_symmetric_file_encryption_and_integrity .................... [PASS]
  -> Authenticated AEAD Encryption & Decryption.
test_5_tamper_detection ........................................... [PASS]
  -> Tamper Detection (Poly1305 tag mismatch aborted decryption).
test_6_ed25519_digital_signature_provenance ....................... [PASS]
  -> Ed25519 Digital Signature & Non-Repudiation Verified.

======================================================================
TEST SUITE: API & Access Control (tests/test_api.py)
======================================================================
test_1_health_status .............................................. [PASS]
  -> System health & crypto status endpoint.
test_2_registration_and_login ..................................... [PASS]
  -> User Registration & JWT Authentication.
test_3_upload_and_download_limits ................................. [PASS]
  -> Upload, Share UUID, & Download Limit Enforcement.

----------------------------------------------------------------------
Ran 9 tests in 1.45s (All Passed - 0 Failures, 0 Errors)
======================================================================
```

---

## 8. Step-by-Step Instructions to Run

### Prerequisites:
* Python 3.10+ (Installed on system)
* VS Code (or any terminal)

### Execution Steps:
1. Open VS Code terminal (`Ctrl + ~`).
2. Navigate to the project directory:
   ```powershell
   cd C:\Users\EBIN\Downloads\fileexchange
   ```
3. Run the automated test suites:
   ```powershell
   python tests/test_crypto.py
   python tests/test_api.py
   ```
4. Start the application:
   ```powershell
   python run_server.py
   ```
5. Open your browser at **`http://127.0.0.1:5000`**.

---

## 9. Conclusion

**SecureFileExchange** provides an enterprise-ready, mathematically verified solution for secure file exchange. By combining **XChaCha20-Poly1305**, **X25519**, **Ed25519**, and **Argon2id** within a clean **7-page architecture**, the application delivers confidentiality, integrity, sender authenticity, and granular access control without unnecessary complexity.
