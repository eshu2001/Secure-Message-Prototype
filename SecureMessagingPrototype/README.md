About the Project:
This project is all about understanding how secure communication works using basic cryptography.
It walks through every step from generating keys to detecting message tampering — using simple Python code.

Task 1 – Digital Signature
This task creates a digital signature system using a simple RSA-style setup.
It helps verify that a message really came from the sender and wasn’t changed.
How to Run:
python Task1.py
Example Output:
Public Key: (e=17, N=3233)
Private Key: (d=2753, N=3233)
Message: HELLO
Signature: 584
✅ Signature Verified! Message is authentic.

Task 2: Diffie–Hellman Exchange
This task combines Diffie-Hellman key exchange with digital signatures from Task 1.
Alice and Bob exchange public values, verify each other’s identities, and end up with the same shared secret key.
How to Run:
python Task2.py
Example Output:
Public DH parameters: p=23, g=5
Public Key: (e=17, N=3233)
Private Key: (d=2753, N=3233)
Alice Public Key: (17, 3233), Private Key: (2753, 3233)
Bob Public Key: (17, 3233), Private Key: (2753, 3233)
Alice secret a = 20
Bob secret b = 22
Alice sends A = 12
Bob sends B = 1
Alice signature on A: 89
Bob signature on B: 289
Alice verified Bob's signature ✅
Bob verified Alice's signature ✅
Alice computes shared secret: 1
Bob computes shared secret: 1
✅ Shared secret successfully established!

Task 3: Encryption Key Derivation
Turns the shared secret from Task 2 into a strong cryptographic key using repeated hashing (SHA-256).
This makes the key harder to guess or break.
How to Run:
python Task3.py
Example Output:
Derived Encryption Key (SHA-256):
ed49df68304314783f66352300a033ed215e0e3f405c96045463b40082a39295

Task 4: Pseudo-Random Number Generation (PRNG)
Creates a simple PRNG that generates random-looking numbers using SHA-256.
It uses the key from Task 3 as the seed to start generating random bytes.
How to Run:
python Task4.py
Example Output:
Random bytes (hex): 3e60559e5686f2f98d1e4dceed16639848f5ee214e33dc76b92f4c7bc632a7eb
PRNG reseeded. New internal state: 214c80fd5c59a76d55dcb38a12ce953d9fe471c8ffbbad30beed100be6874da2
Generated 32 pseudorandom bytes.
New random bytes (hex): 8e67d9fdf6555e6a5016ef6305789c2dc69456ae731948604bd08323275219d1

Task 5: Secure Message Exchange
Now Alice can send an encrypted message to Bob securely!
How to Run:
python Task5.py
Example Output:
Derived AES Key (hex): 1aceb05294f22f1200e588438c62ebd34d31085e76a875f4802a0f6e89443241
Generated IV (hex): 3e60559e5686f2f98d1e4dceed166398
Alice sends:
Ciphertext: 909546cfa1fed6fd8ef2d38e065b61c9e98ba8a27005521ba2457361878615810ed18802120090517ab4030fe3a4e5a5
HMAC Tag: 5befaea68be12bb5e64474a19ccb49ebebf6c262d6d1567222669ee2a5ca1ed0
Bob receives:
Decrypted Message: Hello Bob, this is a secure message!
✅ Message verified — confidentiality & integrity ensured!

Task 6: Tampering experiment
This task shows what happens if someone tries to tamper with an encrypted message.
Bob uses the HMAC from Task 5 to detect changes.
How to Run:
python Task6.py
Example Output:
--- Original message ---
Plaintext: Hello Bob — this message will be tampered!
Ciphertext (hex): 3bc89977cd7a8c3414f96ec665a7382582b011ea04c01e509074296060e3d67db0efe1b7ba54f9314d1b1188566787c0
Tag (hex): 59f9be86473a4ed9ec53283369c77436bab24fb7f1ec3d08504930194e6096ec
[Bob] Verification passed (no tampering). Decrypted text: Hello Bob — this message will be tampered!
--- Tampering ---
Tampered ciphertext (hex): 3ac89977cd7a8c3414f96ec665a7382582b011ea04c01e509074296060e3d67db0efe1b7ba54f9314d1b1188566787c0
[Bob] Integrity check failed as expected. Tampering detected!
Error message: ❌ Integrity check failed! Ciphertext may be tampered.
Original tag == recomputed_tag ? False
Recomputed tag (hex): b4b9cdd72657c452330cff3a3f4f442f6d89d4dc6f494cacfa61d92a400e7c7c