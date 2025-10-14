# Task4.py
import os
import hashlib
from Task3 import key_derivation_function
from Task2 import diffie_hellman_key_exchange


class SimplePRNG:
    def __init__(self, seed: bytes = None):
        """Initialize PRNG with an optional seed."""
        if seed is None:
            seed = os.urandom(32)  # 256-bit default seed
        self.state = hashlib.sha256(seed).digest()
        print(f"PRNG initialized with seed: {self.state.hex()}")

    def reseed(self, new_entropy: bytes = None):
        """Reseed the PRNG with new entropy (mix into current state)."""
        if new_entropy is None:
            new_entropy = os.urandom(32)
        # Mix old state and new entropy
        self.state = hashlib.sha256(self.state + new_entropy).digest()
        print(f"PRNG reseeded. New internal state: {self.state.hex()}")

    def generate(self, n: int):
        """Generate n bytes of pseudorandom data."""
        output = b""
        while len(output) < n:
            # Hash current state to produce new pseudorandom block
            block = hashlib.sha256(self.state).digest()
            output += block
            # Update internal state (for forward secrecy)
            self.state = hashlib.sha256(self.state + block).digest()
        print(f"Generated {n} pseudorandom bytes.")
        return output[:n]


if __name__ == "__main__":
    print("Running Diffie-Hellman (Task2) to get shared secret...\n")
    shared_secret_Alice, shared_secret_Bob = diffie_hellman_key_exchange()

    # Derive key from shared secret using Task3
    print("\nDeriving encryption key using Task3 KDF...\n")
    derived_key = key_derivation_function(shared_secret_Alice, iterations=5000)

    # Initialize PRNG with derived key as seed
    prng = SimplePRNG(seed=derived_key)

    # Generate pseudorandom numbers
    rand_bytes = prng.generate(32)
    print(f"\n Random bytes (hex): {rand_bytes.hex()}")

    # Reseed the PRNG with new randomness
    prng.reseed()

    rand_bytes2 = prng.generate(32)
    print(f"\n New random bytes (hex): {rand_bytes2.hex()}")
