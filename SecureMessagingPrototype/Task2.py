import random
from Task1 import KeyGen, Sign, Verify, H

def diffie_hellman_key_exchange():
    #Public DH parameters
    p = 23
    g = 5
    print(f"Public DH parameters: p={p}, g={g}\n")

    #Generate RSA keys for Alice and Bob
    pub_Alice, priv_Alice = KeyGen()
    pub_Bob, priv_Bob = KeyGen()
    print(f"Alice Public Key: {pub_Alice}, Private Key: {priv_Alice}")
    print(f"Bob Public Key: {pub_Bob}, Private Key: {priv_Bob}\n")

    #Secrets
    a = random.randint(1, p-1)
    b = random.randint(1, p-1)
    print(f"Alice secret a = {a}")
    print(f"Bob secret b = {b}\n")

    #Public values
    A = pow(g, a, p)
    B = pow(g, b, p)
    print(f"Alice sends A = {A}")
    print(f"Bob sends B = {B}\n")

    #Signatures
    sig_A = Sign(priv_Alice[0], priv_Alice[1], str(A))
    sig_B = Sign(priv_Bob[0], priv_Bob[1], str(B))
    print(f"Alice signature on A: {sig_A}")
    print(f"Bob signature on B: {sig_B}\n")

    #Verification
    if Verify(pub_Bob[0], pub_Bob[1], str(B), sig_B):
        print("Alice verified Bob's signature ✅")
    else:
        print("Alice failed to verify Bob's signature ❌")

    if Verify(pub_Alice[0], pub_Alice[1], str(A), sig_A):
        print("Bob verified Alice's signature ✅")
    else:
        print("Bob failed to verify Alice's signature ❌")
    print()

    #Compute shared secrets
    shared_secret_Alice = pow(B, a, p)
    shared_secret_Bob = pow(A, b, p)
    print(f"Alice computes shared secret: {shared_secret_Alice}")
    print(f"Bob computes shared secret: {shared_secret_Bob}")

    if shared_secret_Alice == shared_secret_Bob:
        print("\n✅ Shared secret successfully established!")
    else:
        print("\n❌ Shared secret mismatch!")

    # 👉 Return both secrets for Task 3
    return shared_secret_Alice, shared_secret_Bob


# Keep this so Task2 can still run standalone
if __name__ == "__main__":
    diffie_hellman_key_exchange()
