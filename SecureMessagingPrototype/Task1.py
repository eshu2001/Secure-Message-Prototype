import math
def KeyGen():
    # Step 1: Choose two primes (use small ones for demo)
    p = 61
    q = 53

    # Step 2: Compute N and phi(N)
    N = p * q
    phi = (p - 1) * (q - 1)

    # Step 3: Choose public exponent e (must be coprime with phi)
    e = 17
    # Step 4: Compute private exponent d (modular inverse of e mod phi)
    d = pow(e, -1, phi)

    print(f"Public Key: (e={e}, N={N})")
    print(f"Private Key: (d={d}, N={N})")

    return (e, N), (d, N)

def H(M, N=None):
    # Convert M to string if it's not already
    M_str = str(M)
    hash_value = sum(bytearray(M_str.encode()))
    if N:
        return hash_value % N
    return hash_value

def Sign(d, N, M):
    h = H(M, N)
    sig = pow(h, d, N)
    return sig

# ----------------------------
# Verify Function
# ----------------------------
def Verify(e, N, M, sig):
    h = H(M, N)
    verified = pow(sig, e, N)
    return h == verified


# ----------------------------
# Test the System
# ----------------------------
if __name__ == "__main__":
    # Key generation
    (e, N), (d, N_priv) = KeyGen()

    # Message
    message = "HELLO"

    # Signing
    signature = Sign(d, N_priv, message)
    print(f"\nMessage: {message}")
    print(f"Signature: {signature}")

    # Verifying
    if Verify(e, N, message, signature):
        print("\n✅ Signature Verified! Message is authentic.")
    else:
        print("\n❌ Signature Verification Failed!")
