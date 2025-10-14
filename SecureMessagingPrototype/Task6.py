# Task6.py
# Tampering experiment: modify ciphertext and check that HMAC detection fails.

from Task2 import diffie_hellman_key_exchange
from Task3 import key_derivation_function
from Task4 import SimplePRNG
from Task5 import authenticated_encrypt, authenticated_decrypt, compute_hmac

def tampering_experiment():
    # 1) Get shared secret (DH)
    shared_secret_A, shared_secret_B = diffie_hellman_key_exchange()

    # 2) Derive symmetric key (KDF, Task3)
    derived_key = key_derivation_function(shared_secret_A, iterations=5000)

    # 3) Initialize PRNG (Task4) and get IV
    prng = SimplePRNG(seed=derived_key)
    iv = prng.generate(16)

    # 4) Alice encrypts a message and computes HMAC (Task5 authenticated_encrypt)
    message = "Hello Bob — this message will be tampered!"
    ciphertext, tag = authenticated_encrypt(derived_key, message, iv)

    print("\n--- Original message ---")
    print("Plaintext:", message)
    print("Ciphertext (hex):", ciphertext.hex())
    print("Tag (hex):", tag.hex())

    # 5) Bob verifies and decrypts (should succeed)
    try:
        plaintext = authenticated_decrypt(derived_key, ciphertext, tag, iv)
        print("\n[Bob] Verification passed (no tampering). Decrypted text:", plaintext)
    except ValueError as e:
        print("\n[Bob] Verification failed (unexpected):", e)

    # 6) Mallory tampers with ciphertext: flip one byte
    tampered = bytearray(ciphertext)
    tampered[0] = tampered[0] ^ 0x01  # flip least significant bit of first byte
    tampered = bytes(tampered)
    print("\n--- Tampering ---")
    print("Tampered ciphertext (hex):", tampered.hex())

    # 7) Bob receives tampered ciphertext and checks HMAC/decrypt
    try:
        plaintext = authenticated_decrypt(derived_key, tampered, tag, iv)
        print("\n[Bob] Decrypted text (unexpected):", plaintext)
    except ValueError as e:
        print("\n[Bob] Integrity check failed as expected. Tampering detected!")
        print("Error message:", e)

    # Extra check: recompute tag on tampered ciphertext (attacker cannot produce original tag)
    recomputed_tag = compute_hmac(derived_key, tampered)
    print("\nOriginal tag == recomputed_tag ?", recomputed_tag == tag)
    print("Recomputed tag (hex):", recomputed_tag.hex())

if __name__ == "__main__":
    tampering_experiment()
