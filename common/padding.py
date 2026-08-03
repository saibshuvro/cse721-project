"""PKCS#7 padding for educational DES/AES text wrappers."""

from __future__ import annotations


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad bytes to a multiple of ``block_size``."""

    raise NotImplementedError("Implement PKCS#7 padding")


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Validate and remove PKCS#7 padding."""

    raise NotImplementedError("Implement strict PKCS#7 unpadding")

