# Task5.py
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Task4 import SimplePRNG
from Task3 import key_derivation_function
from Task2 import diffie_hellman_key_exchange


# --- Symmetric Encryption and Decryption ---
def sym_enc(key: bytes, plaintext: str, iv: bytes) -> bytes:
    """Encrypt plaintext using AES (CBC mode)."""
    # Padding (PKCS7)
    pad_len = 16 - (len(plaintext.encode()) % 16)
    padded = plaintext.encode() + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext


def sym_dec(key: bytes, ciphertext: bytes, iv: bytes) -> str:
    """Decrypt ciphertext using AES (CBC mode)."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    plaintext = padded[:-pad_len].decode()
    return plaintext


# --- HMAC ---
def compute_hmac(key: bytes, message: bytes) -> bytes:
    """Compute HMAC using SHA-256."""
    return hmac.new(key, message, hashlib.sha256).digest()


# --- Authenticated Encryption (Encrypt-then-MAC) ---
def authenticated_encrypt(key: bytes, plaintext: str, iv: bytes):
    """Encrypt plaintext and compute HMAC tag."""
    ciphertext = sym_enc(key, plaintext, iv)
    tag = compute_hmac(key, ciphertext)
    return ciphertext, tag


def authenticated_decrypt(key: bytes, ciphertext: bytes, tag: bytes, iv: bytes):
    """Verify HMAC tag and decrypt ciphertext."""
    calc_tag = compute_hmac(key, ciphertext)
    if not hmac.compare_digest(calc_tag, tag):
        raise ValueError("❌ Integrity check failed! Ciphertext may be tampered.")
    return sym_dec(key, ciphertext, iv)


# --- Secure Message Exchange Simulation ---
def secure_message_exchange():
    # Step 1: Shared secret via Diffie–Hellman (Task2)
    shared_secret_Alice, shared_secret_Bob = diffie_hellman_key_exchange()

    # Step 2: Derive AES key via KDF (Task3)
    derived_key = key_derivation_function(shared_secret_Alice, iterations=5000)

    # Step 3: Initialize PRNG (Task4) and generate IV
    prng = SimplePRNG(seed=derived_key)
    iv = prng.generate(16)

    print("\n--- Secure Message Exchange ---")
    print(f"Derived AES Key (hex): {derived_key.hex()}")
    print(f"Generated IV (hex): {iv.hex()}")

    # Step 4: Alice encrypts a message
    message = "Hello Bob, this is a secure message!"
    ciphertext, tag = authenticated_encrypt(derived_key, message, iv)

    print("\n Alice sends:")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"HMAC Tag: {tag.hex()}")

    # Step 5: Bob decrypts and verifies
    try:
        plaintext = authenticated_decrypt(derived_key, ciphertext, tag, iv)
        print("\n Bob receives:")
        print(f"Decrypted Message: {plaintext}")
        print("✅ Message verified — confidentiality & integrity ensured!")
    except ValueError as e:
        print(str(e))


if __name__ == "__main__":
    secure_message_exchange()
