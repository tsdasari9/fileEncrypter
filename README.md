#  ChaCha20-Poly1305 File Encryptor

A simple Rust CLI tool to encrypt and decrypt files using **ChaCha20-Poly1305** for authenticated encryption and **Argon2** for password-based key derivation.  

It’s lightweight, fast, and easy to use — designed for secure personal file encryption.

---

## Features
- **Authenticated Encryption** — Ensures confidentiality & integrity.
- **Password-Based Key Derivation** — Argon2 with a random salt.
- **Per-file Random Nonce** — Secure AEAD mode usage.
- **Base64 Output** — Easy to store or copy across systems.
- **Minimal CLI** — `encrypt` / `decrypt`.

---

## Installation

**Prerequisites**
- Rust (stable)

**Clone & build**
```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
cargo build --release
```

The binary will be in:
```
./target/release/chacha20-file-encryptor
```

---

## Usage

### Encrypt a file
```bash
./chacha20-file-encryptor encrypt <file_path> <password>
```
**Example**
```bash
./chacha20-file-encryptor encrypt secret.txt "correct horse battery staple"
# Output: secret.txt.enc
```

### Decrypt a file
```bash
./chacha20-file-encryptor decrypt <encrypted_file_path> <password>
```
**Example**
```bash
./chacha20-file-encryptor decrypt secret.txt.enc "correct horse battery staple"
# Output: secret.txt
```

---

## How It Works
**Key Derivation:**  
Argon2 hashes the password with a random 16-byte salt → 32-byte key.  

**Encryption:**  
ChaCha20-Poly1305 with a random 12-byte nonce.  

**File Format (before Base64):**  
```
[ 16-byte salt ][ 12-byte nonce ][ ciphertext || 16-byte Poly1305 tag ]
```

---

## Security Notes
- Avoid passing passwords directly in the shell if possible (history/process lists risk).  
- Uses Argon2 default params — for production, consider Argon2id with higher memory/time cost.  
- A fresh random nonce is generated for every encryption (critical for security).  
- Decryption will fail if password, salt, nonce, or ciphertext are wrong or corrupted.  
- The program currently loads the whole file into memory (no streaming).  

---

## Dependencies
- chacha20poly1305  
- argon2  
- rand  
- base64  

---

