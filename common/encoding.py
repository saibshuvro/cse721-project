"""Explicit conversions used by block ciphers and public-key demonstrations."""

from __future__ import annotations


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings, rejecting different lengths."""

    raise NotImplementedError("Implement byte-wise XOR")


def split_blocks(data: bytes, block_size: int) -> tuple[bytes, ...]:
    """Split already-aligned input into fixed-size blocks."""

    raise NotImplementedError("Implement aligned block splitting")

