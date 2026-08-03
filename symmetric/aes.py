"""AES-128 primitives, key expansion, inverse operations, and text wrappers."""

from __future__ import annotations

from dataclasses import dataclass


BLOCK_SIZE = 16
KEY_SIZE = 16
ROUND_COUNT = 10


@dataclass(frozen=True)
class AESTrace:
    """AES-128 round keys and state snapshots for display and testing."""

    round_keys: tuple[bytes, ...]
    round_states: tuple[bytes, ...]


def generate_key() -> bytes:
    """Generate a 16-byte AES-128 key using ``secrets``."""

    raise NotImplementedError("Implement AES-128 key generation")


def expand_key(key: bytes) -> tuple[bytes, ...]:
    """Expand a 16-byte key into eleven 16-byte round keys."""

    raise NotImplementedError("Implement AES-128 key expansion")


def encrypt_block(block: bytes, key: bytes) -> tuple[bytes, AESTrace]:
    """Encrypt one 16-byte block and return its trace."""

    raise NotImplementedError("Implement AES-128 block encryption")


def decrypt_block(block: bytes, key: bytes) -> tuple[bytes, AESTrace]:
    """Decrypt one 16-byte block using inverse transforms."""

    raise NotImplementedError("Implement AES-128 block decryption")

