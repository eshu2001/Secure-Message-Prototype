# Task5_two_party.py
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Task4 import SimplePRNG
from Task3 import key_derivation_function
from Task2 import diffie_hellman_key_exchange

# --- Symmetric Encryption and Decryption ---
def sym_enc(key: bytes, plaintext: str, iv: bytes) -> bytes:
    pad_len = 16 - (len(plaintext.encode()) % 16)
    padded = plaintext.encode() + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext

def sym_dec(key: bytes, ciphertext: bytes, iv: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    plaintext = padded[:-pad_len].decode()
    return plaintext

# --- HMAC ---
def compute_hmac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

# --- Authenticated Encryption ---
def authenticated_encrypt(key: bytes, plaintext: str, iv: bytes):
    ciphertext = sym_enc(key, plaintext, iv)
    tag = compute_hmac(key, ciphertext)
    return ciphertext, tag

def authenticated_decrypt(key: bytes, ciphertext: bytes, tag: bytes, iv: bytes):
    calc_tag = compute_hmac(key, ciphertext)
    if not hmac.compare_digest(calc_tag, tag):
        raise ValueError("❌ Integrity check failed! Ciphertext may be tampered.")
    return sym_dec(key, ciphertext, iv)

# --- Two-Party Protocol Simulation ---
def two_party_protocol():
    print("\n=== Step 1: Establish Shared Secret via Diffie-Hellman ===")
    shared_secret_Alice, shared_secret_Bob = diffie_hellman_key_exchange()

    # Step 2: Derive AES session key
    session_key = key_derivation_function(shared_secret_Alice, iterations=5000)

    # Step 3: Initialize PRNG to generate IV
    prng = SimplePRNG(seed=session_key)
    iv = prng.generate(16)

    print("\n=== Alice Terminal ===")
    message = "Hello Bob, this is a secure message!"
    ciphertext, tag = authenticated_encrypt(session_key, message, iv)
    print(f"Alice encrypts message: {ciphertext.hex()}")
    print(f"Alice computes HMAC tag: {tag.hex()}")
    print(f"Alice sends (ciphertext, tag, iv) → Bob\n")

    # Simulate copying values to Bob terminal
    ciphertext_received = ciphertext
    tag_received = tag
    iv_received = iv

    print("=== Bob Terminal ===")
    try:
        decrypted = authenticated_decrypt(session_key, ciphertext_received, tag_received, iv_received)
        print(f"Bob decrypts message: {decrypted}")
        print("✅ Message verified — confidentiality & integrity ensured!")
    except ValueError as e:
        print(str(e))


if __name__ == "__main__":
    two_party_protocol()
