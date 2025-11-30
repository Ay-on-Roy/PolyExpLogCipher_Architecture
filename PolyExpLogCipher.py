import math
import hashlib
import os
import time
from typing import List, Dict, Tuple, Optional

from argon2.low_level import hash_secret_raw, Type


class PolyExpLogCipher:

    def __init__(self, passphrase: str, prime: int = 15485863) -> None:
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")
        if not self._is_prime(prime):
            raise ValueError("Modulus must be a prime number")

        self.p = prime
        self.passphrase = passphrase
        self.k = self._derive_key(passphrase)
        self.k_prime = self.k % 1000
        self.nonce: Optional[int] = None
        self._nonce_hash_cache: Optional[int] = None
        self._poly_table_cache: Optional[Dict[int, Tuple[int, int]]] = None

    @staticmethod
    def _is_prime(n: int) -> bool:
        if n < 2:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def _derive_key(self, passphrase: str) -> int:
        salt = os.urandom(16)
        hash_bytes = hash_secret_raw(
            secret=passphrase.encode('utf-8'),
            salt=salt,
            time_cost=4,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        k = int.from_bytes(hash_bytes, 'big') % (self.p - 1)
        while math.gcd(k, self.p - 1) != 1:
            k = (k + 1) % (self.p - 1)
        return k

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        def extended_gcd(x: int, y: int) -> Tuple[int, int, int]:
            if x == 0:
                return y, 0, 1
            gcd, x1, y1 = extended_gcd(y % x, x)
            x2 = y1 - (y // x) * x1
            return gcd, x2, x1

        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m

    def _hidden_custom_equation(self, m: int, k: int) -> int:
        mod_factor = (m + 1) if (m + 1) != 0 else 1
        secret_val = ((m ^ k) * (k % mod_factor) + (m**2 + k**2)) % self.p
        return secret_val

    def _wave_function(self, m: int, k: int) -> int:
        A, B, C = 1000, 0.1, 0.05
        wave_val = int(A * math.sin(B * m + C * k))
        return wave_val % self.p

    def _logarithmic_layer(self, m: int, k: int) -> int:
        scale = 100
        adjusted = (m + 1 + (k % 10)) % self.p
        log_val = int(scale * (adjusted - (adjusted**2 / 2) + (adjusted**3 / 3))) % self.p
        return log_val

    def _extra_exponential_layer(self, m: int, k: int) -> int:
        return pow(3, m + (k % 10), self.p)

    def _build_poly_table(self, max_m: int = 255) -> Dict[int, Tuple[int, int]]:
        if self._poly_table_cache is not None:
            return self._poly_table_cache
        if self._nonce_hash_cache is None:
            raise ValueError("Nonce hash cache missing. Generate nonce first.")

        poly_table: Dict[int, Tuple[int, int]] = {}
        nonce_hash = self._nonce_hash_cache

        start_time = time.time()
        for m in range(max_m + 1):
            try:
                mix_val = (m + nonce_hash) % self.p
                e = pow(mix_val, self.k, self.p)
                c1 = (e**3 + self.k * e**2 + self.k**2 * m) % self.p
                hidden_val = self._hidden_custom_equation(m, self.k)
                wave_val = self._wave_function(m, self.k)
                log_val = self._logarithmic_layer(m, self.k)
                exp_val = self._extra_exponential_layer(m, self.k)
                c_final = (c1 + hidden_val + wave_val + log_val + exp_val) % self.p
                poly_table[c_final] = (e, m)
            except (OverflowError, ValueError):
                continue
        elapsed = time.time() - start_time
        print(f"[Info] Decryption table built in {elapsed:.2f} seconds.")
        self._poly_table_cache = poly_table
        return poly_table

    def generate_nonce(self) -> int:
        self.nonce = int.from_bytes(os.urandom(16), 'big') % (self.p - 1)
        self._nonce_hash_cache = int(hashlib.sha256(str(self.nonce).encode()).hexdigest(), 16)
        self._poly_table_cache = None
        return self.nonce

    def encrypt(self, plaintext_bytes: bytes) -> List[int]:
        if not plaintext_bytes:
            return []
        if self.nonce is None or self._nonce_hash_cache is None:
            raise ValueError("Nonce must be generated before encryption")

        ciphertext: List[int] = []
        nonce_hash = self._nonce_hash_cache

        for m in plaintext_bytes:
            try:
                mix_val = (m + nonce_hash) % self.p
                e = pow(mix_val, self.k, self.p)
                c1 = (e**3 + self.k * e**2 + self.k**2 * m) % self.p
                hidden_val = self._hidden_custom_equation(m, self.k)
                wave_val = self._wave_function(m, self.k)
                log_val = self._logarithmic_layer(m, self.k)
                exp_val = self._extra_exponential_layer(m, self.k)
                c_final = (c1 + hidden_val + wave_val + log_val + exp_val) % self.p
                ciphertext.append(c_final)
            except (OverflowError, ValueError):
                ciphertext.append(0)
        return ciphertext

    def decrypt(self, ciphertext: List[int]) -> bytes:
        if not ciphertext:
            return b''
        if self.nonce is None or self._nonce_hash_cache is None:
            raise ValueError("Nonce must be set before decryption")

        poly_table = self._build_poly_table(max_m=255)
        plaintext_bytes = bytearray()
        for c in ciphertext:
            if c in poly_table:
                _, m = poly_table[c]
                if 0 <= m <= 255:
                    plaintext_bytes.append(m)
                else:
                    plaintext_bytes.append(ord('?'))
            else:
                plaintext_bytes.append(ord('?'))
        return bytes(plaintext_bytes)

    def encrypt_to_string(self, plaintext_bytes: bytes) -> str:
        ciphertext = self.encrypt(plaintext_bytes)
        hex_parts = [f"{c:06x}" for c in ciphertext]
        return "".join(hex_parts)

    def decrypt_from_string(self, cipher_string: str) -> bytes:
        ciphertext = [int(cipher_string[i:i+6], 16) for i in range(0, len(cipher_string), 6)]
        return self.decrypt(ciphertext)
