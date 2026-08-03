"""RSA number theory, key generation, safe block bounds, and textbook operations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PublicKey:
    exponent: int
    modulus: int


@dataclass(frozen=True)
class PrivateKey:
    exponent: int
    modulus: int


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey
    prime_p: int
    prime_q: int


def generate_keypair(bits: int, public_exponent: int = 65_537) -> KeyPair:
    """Generate two probable primes and an RSA key pair of approximately ``bits`` bits."""

    raise NotImplementedError("Implement RSA key generation")


def encrypt_int(message: int, key: PublicKey) -> int:
    """Encrypt an integer satisfying ``0 <= message < modulus``."""

    raise NotImplementedError("Implement textbook RSA integer encryption")


def decrypt_int(ciphertext: int, key: PrivateKey) -> int:
    """Decrypt an integer satisfying ``0 <= ciphertext < modulus``."""

    raise NotImplementedError("Implement textbook RSA integer decryption")


def encrypt_text(plaintext: str, key: PublicKey) -> list[int]:
    """Encode UTF-8 into reversible modulus-bounded blocks, then encrypt them."""

    raise NotImplementedError("Implement length-safe RSA text encryption")


def decrypt_text(ciphertext: list[int], key: PrivateKey) -> str:
    """Decrypt and reconstruct length-safe UTF-8 blocks."""

    raise NotImplementedError("Implement length-safe RSA text decryption")

