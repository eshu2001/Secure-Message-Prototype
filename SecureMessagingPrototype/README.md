**About the Project:**
This project is all about understanding how secure communication works using basic cryptography.
It walks through every step from generating keys to detecting message tampering using simple Python code.

**Task 1 – Digital Signature**
**Goal:** Implement a simple RSA signature system.
**What I did:**
Generated RSA public/private keys for Alice and Bob.
Signed a message with Alice’s private key.
Verified the signature using Alice’s public key.
Also verified what happens when using a wrong key.
**Output:** Shows public/private keys, message, signature, and verification results.

**Task 2: Diffie–Hellman Exchange**
**Goal:** Establish a shared secret between Alice and Bob securely.
**What I did:**
Implemented DH key exchange with fixed prime p and generator g.
Alice and Bob generated their secrets and exchanged values.
Each side signed their DH value with RSA to ensure authenticity.
Verified the signatures and computed the shared secret.
**Output:** Shows intermediate values ga mod p, gb mod p, signatures, and final shared secret.

**Task 3: Encryption Key Derivation**
**Goal:** Derive a secure symmetric key from the DH shared secret.
**What I did:**
Converted the shared secret into bytes.
Applied iterative SHA-256 hashing (10,000 iterations) to get a 256-bit key.
**Output:** Shows the derived key in hexadecimal.

**Task 4: Pseudo-Random Number Generation (PRNG)**
**Goal:** Demonstrate pseudorandom number generation, determinism, and seeding.
**What I did:**
Implemented a simple PRNG using SHA-256.
Generated random sequences without a seed → truly random.
Generated sequences with the same seed → deterministic output.
Generated sequences with different seeds → showed seeding impact.
**Output:** Multiple sequences of random bytes, showing randomness, determinism, and reseeding.

**Task 5: Secure Message Exchange**
**Goal:** Implement secure message exchange with confidentiality and integrity.
**What I did:**
Used DH + KDF to get a shared AES key.
Alice encrypts a message with AES-CBC and generates an HMAC tag.
Bob verifies the HMAC and decrypts the message.
Simulated two terminals for Alice and Bob for easy screenshots.
**Output:** Shows ciphertext, HMAC, IV, and decrypted message at Bob’s end.

**Task 6: Tampering experiment**
Could extend this project by:
Implement network communication instead of simulating copy-paste between terminals.
Introduce session key rotation to improve security over multiple messages.
Support multiple messages with forward secrecy.
Extend tamper detection to all messages automatically, not just a single test message.

**How to Run**:
**Make sure you have all required packages:**
pip install pycryptodome cryptography sympy
**Run tasks in order:**
python Task1.py
python Task2.py
python Task3.py
python Task4.py
python Task5.py

