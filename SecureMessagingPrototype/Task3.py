# Task3.py
import hashlib
from Task2 import diffie_hellman_key_exchange  # reuse Task2 for shared secret

def int_to_bytes(x: int) -> bytes:
    """Convert integer to big-endian bytes."""
    if x == 0:
        return b'\x00'
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def key_derivation_function(shared_secret, iterations=10000):
    """
    Simple KDF using iterative SHA-256 hashing.
    
    Args:
        shared_secret (int): Shared secret from Diffie-Hellman.
        iterations (int): Number of times to hash.
    
    Returns:
        bytes: Final derived key (32 bytes).
    """
    # Convert integer secret to bytes
    key = int_to_bytes(shared_secret)

    # Iteratively hash
    for _ in range(iterations):
        key = hashlib.sha256(key).digest()
    
    return key

if __name__ == "__main__":
    print("Running Diffie-Hellman (Task2) to get shared secret...\n")

    # Run Task2 to get shared secret values
    # Modify Task2 function to return shared secrets if not already
    shared_secret_Alice, shared_secret_Bob = diffie_hellman_key_exchange()

    # Both should be equal, so we can use either
    derived_key = key_derivation_function(shared_secret_Alice, iterations=10000)

    print("\n Derived Encryption Key (SHA-256):")
    print(derived_key.hex())
