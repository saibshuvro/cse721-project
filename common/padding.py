"""Guided PKCS#7 padding helpers shared by DES and AES text wrappers."""

from __future__ import annotations


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Pad bytes to a multiple of ``block_size``.

    Example for an 8-byte block: ``b"HELLO"`` receives three ``0x03`` bytes.
    """
    if type(data) is not bytes:
        raise TypeError(f"data must be bytes, not {type(data).__name__}")

    # A padding length is stored in one byte, so PKCS#7 supports block sizes
    # from 1 through 255 bytes. Checking the exact type also rejects booleans,
    # even though bool is a subclass of int in Python.
    if type(block_size) is not int:
        raise TypeError(
            f"block_size must be an integer, not {type(block_size).__name__}"
        )
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size must be from 1 through 255")

    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Strictly validate and remove PKCS#7 padding.

    Never use ``rstrip`` for cryptographic padding; it can remove legitimate
    message bytes and can accept malformed padding.
    """
    if type(data) is not bytes:
        raise TypeError(f"data must be bytes, not {type(data).__name__}")

    if type(block_size) is not int:
        raise TypeError(
            f"block_size must be an integer, not {type(block_size).__name__}"
        )
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size must be from 1 through 255")

    # Properly padded data contains at least one complete block and its total
    # length is always a multiple of the chosen block size.
    if len(data) == 0:
        raise ValueError("padded data must not be empty")
    if len(data) % block_size != 0:
        raise ValueError("padded data length must be a multiple of block_size")

    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("invalid PKCS#7 padding length")

    expected_padding = bytes([padding_length]) * padding_length
    if data[-padding_length:] != expected_padding:
        raise ValueError("invalid PKCS#7 padding bytes")

    return data[:-padding_length]
