"""DES primitives, key schedule, traces, and text wrappers.

Raw functions use 8-byte blocks. Core logic must not delegate to a crypto library.
"""

from __future__ import annotations

from dataclasses import dataclass


BLOCK_SIZE = 8
ROUND_COUNT = 16


@dataclass(frozen=True)
class DESTrace:
    """The round keys and intermediate state needed for a coursework demonstration."""

    round_keys: tuple[int, ...]
    round_states: tuple[tuple[int, int], ...]


def generate_key() -> bytes:
    """Generate an odd-parity, non-weak DES key using ``secrets``."""

    raise NotImplementedError("Implement DES key generation")


def expand_key(key: bytes) -> tuple[int, ...]:
    """Return sixteen 48-bit round keys."""

    raise NotImplementedError("Implement the DES key schedule")


def encrypt_block(block: bytes, key: bytes) -> tuple[bytes, DESTrace]:
    """Encrypt one 8-byte block and return its trace."""

    raise NotImplementedError("Implement DES block encryption")


def decrypt_block(block: bytes, key: bytes) -> tuple[bytes, DESTrace]:
    """Decrypt one 8-byte block using the reverse round-key order."""

    raise NotImplementedError("Implement DES block decryption")

