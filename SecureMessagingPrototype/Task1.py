from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# ----------------------------
# RSA Functions (Signing Only)
# ----------------------------
def KeyGen(p, q, e):
    N = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return (e, N), (d, N)

def H(M, N=None):
    M_str = str(M)
    hash_value = sum(bytearray(M_str.encode()))
    if N:
        return hash_value % N
    return hash_value

def Sign(d, N, M):
    h = H(M, N)
    sig = pow(h, d, N)
    return sig

def Verify(e, N, M, sig):
    h = H(M, N)
    verified = pow(sig, e, N)
    return h == verified

# ----------------------------
# AES Functions
# ----------------------------
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(key, b64_message):
    raw = base64.b64decode(b64_message)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# ----------------------------
# Task1: Two-Party Protocol (AES + RSA Signature)
# ----------------------------
def main():
    print("=== Key Generation ===")
    # Fixed large primes for RSA (demo signing)
    # Alice
    p_a, q_a, e_a = 10007, 10009, 65537
    (e_a, N_a), (d_a, N_a_priv) = KeyGen(p_a, q_a, e_a)
    print(f"Alice Public Key: (e={e_a}, N={N_a})")

    # Bob
    p_b, q_b, e_b = 10037, 10039, 65537
    (e_b, N_b), (d_b, N_b_priv) = KeyGen(p_b, q_b, e_b)
    print(f"Bob Public Key: (e={e_b}, N={N_b})")

    # ----------------------------
    # Alice generates AES session key
    # ----------------------------
    session_key = get_random_bytes(16)  # AES-128
    print("\n=== Alice Terminal ===")
    print(f"Alice generates AES session key: {session_key.hex()}")

    # (Simulate sending session key securely)
    print(f"Alice sends session key to Bob (simulated)")

    # Alice encrypts message
    message = "HELLO BOB"
    ciphertext = aes_encrypt(session_key, message)
    print(f"Alice encrypts message: {ciphertext}")

    # Alice signs the message
    signature = Sign(d_a, N_a_priv, message)
    print(f"Alice signs message: {signature}")

    # ----------------------------
    # Bob decrypts message
    # ----------------------------
    print("\n=== Bob Terminal ===")
    print(f"Bob receives session key: {session_key.hex()}")
    plaintext = aes_decrypt(session_key, ciphertext)
    print(f"Bob decrypts message: {plaintext}")

    # Verify signature with correct key
    if Verify(e_a, N_a, plaintext, signature):
        print("✅ Signature Verified! Message is authentic.")
    else:
        print("❌ Signature Verification Failed!")

    # Verify signature with WRONG key
    wrong_e, wrong_N = 65537, N_a + 1  # intentionally wrong
    if Verify(wrong_e, wrong_N, plaintext, signature):
        print("❌ Verification incorrectly succeeded with wrong key!")
    else:
        print("✅ Verification failed as expected with wrong key.")

if __name__ == "__main__":
    main()
