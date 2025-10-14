import random
from Task1 import KeyGen, Sign, Verify

def diffie_hellman_key_exchange():
    print("=== Public Parameters ===")
    p = 23
    g = 5
    print(f"Public DH parameters: p = {p}, g = {g}")

    # ----------------------------
    # RSA Key Generation for Alice & Bob
    # ----------------------------
    print("\n=== Key Generation ===")
    # Use same primes as Task1 to stay consistent
    p_a, q_a, e_a = 10007, 10009, 65537
    (eA, NA), (dA, NA_priv) = KeyGen(p_a, q_a, e_a)
    print(f"Alice Public Key: (e={eA}, N={NA})")

    p_b, q_b, e_b = 10037, 10039, 65537
    (eB, NB), (dB, NB_priv) = KeyGen(p_b, q_b, e_b)
    print(f"Bob Public Key: (e={eB}, N={NB})")

    # ----------------------------
    # Alice Terminal
    # ----------------------------
    print("\n=== Alice Terminal ===")
    a = random.randint(1, p-1)
    A = pow(g, a, p)
    print(f"Alice secret a = {a}")
    print(f"Alice computes A = g^a mod p = {A}")

    sig_A = Sign(dA, NA_priv, str(A))
    print(f"Alice signs A with her private key: signature = {sig_A}")
    print(f"Alice sends (A={A}, sig_A={sig_A}) → Bob")

    # ----------------------------
    # Bob Terminal
    # ----------------------------
    print("\n=== Bob Terminal ===")
    b = random.randint(1, p-1)
    B = pow(g, b, p)
    print(f"Bob secret b = {b}")
    print(f"Bob computes B = g^b mod p = {B}")

    sig_B = Sign(dB, NB_priv, str(B))
    print(f"Bob signs B with his private key: signature = {sig_B}")
    print(f"Bob sends (B={B}, sig_B={sig_B}) → Alice")

    # ----------------------------
    # Verification and Shared Secret Calculation
    # ----------------------------
    print("\n=== Verification Phase ===")

    # Alice verifies Bob's signature
    print("\n-- Alice verifies Bob's value --")
    if Verify(eB, NB, str(B), sig_B):
        print(f"✅ Alice verified Bob’s signature for B={B}")
    else:
        print(f"❌ Alice failed to verify Bob’s signature!")

    # Bob verifies Alice's signature
    print("\n-- Bob verifies Alice's value --")
    if Verify(eA, NA, str(A), sig_A):
        print(f"✅ Bob verified Alice’s signature for A={A}")
    else:
        print(f"❌ Bob failed to verify Alice’s signature!")

    # ----------------------------
    # Shared Secret Computation
    # ----------------------------
    shared_secret_Alice = pow(B, a, p)
    shared_secret_Bob = pow(A, b, p)

    print("\n=== Shared Secret Computation ===")
    print(f"Alice computes shared secret s = B^a mod p = {shared_secret_Alice}")
    print(f"Bob computes shared secret s = A^b mod p = {shared_secret_Bob}")

    if shared_secret_Alice == shared_secret_Bob:
        print("\n✅ Shared secret successfully established and matches on both sides!")
    else:
        print("\n❌ Shared secret mismatch!")
            # ✅ Return shared secrets for use in Task3
    return shared_secret_Alice, shared_secret_Bob


if __name__ == "__main__":
    diffie_hellman_key_exchange()
