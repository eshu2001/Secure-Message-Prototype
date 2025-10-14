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
            print("No seed provided — generating true random seed.")
        self.state = hashlib.sha256(seed).digest()
        print(f"PRNG initialized with seed: {self.state.hex()}")

    def reseed(self, new_entropy: bytes = None):
        """Reseed the PRNG with new entropy (mix into current state)."""
        if new_entropy is None:
            new_entropy = os.urandom(32)
        self.state = hashlib.sha256(self.state + new_entropy).digest()
        print(f"PRNG reseeded. New internal state: {self.state.hex()}")

    def generate(self, n: int):
        """Generate n bytes of pseudorandom data."""
        output = b""
        while len(output) < n:
            block = hashlib.sha256(self.state).digest()
            output += block
            self.state = hashlib.sha256(self.state + block).digest()
        print(f"Generated {n} pseudorandom bytes.")
        return output[:n]


if __name__ == "__main__":
    print("=== Running Diffie-Hellman (Task2) to get shared secret ===\n")
    shared_secret_Alice, shared_secret_Bob = diffie_hellman_key_exchange()

    print("\n=== Deriving encryption key using Task3 KDF ===\n")
    derived_key = key_derivation_function(shared_secret_Alice, iterations=5000)

    print("\n=== RANDOMNESS DEMONSTRATION ===")
    prng = SimplePRNG(seed=derived_key)
    rand_bytes1 = prng.generate(32)
    print(f"Random bytes (hex): {rand_bytes1.hex()}")
    prng.reseed()
    rand_bytes2 = prng.generate(32)
    print(f"New random bytes after reseed (hex): {rand_bytes2.hex()}\n")

    print("=== DETERMINISM DEMONSTRATION (Same Seed) ===")
    prng1 = SimplePRNG(seed=b"fixed_seed")
    seq1 = prng1.generate(32)

    prng2 = SimplePRNG(seed=b"fixed_seed")
    seq2 = prng2.generate(32)

    print(f"Sequence 1: {seq1.hex()}")
    print(f"Sequence 2: {seq2.hex()}")
    print(f"Identical? {seq1 == seq2}\n")

    print("=== SEEDING IMPACT DEMONSTRATION (Different Seeds) ===")
    prng3 = SimplePRNG(seed=b'seed_one')
    seq3 = prng3.generate(32)

    prng4 = SimplePRNG(seed=b'seed_two')
    seq4 = prng4.generate(32)

    print(f"Sequence 1: {seq3.hex()}")
    print(f"Sequence 2: {seq4.hex()}")
    print(f"Identical? {seq3 == seq4}\n")
