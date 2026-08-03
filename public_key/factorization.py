"""Factorization attacks intended only for deliberately small RSA moduli."""

from __future__ import annotations


def trial_division(modulus: int) -> tuple[int, int] | None:
    """Return non-trivial factors when a small semiprime is tractable."""

    raise NotImplementedError("Implement bounded trial division")


def recover_private_exponent(modulus: int, public_exponent: int) -> int:
    """Factor a toy modulus and recover its RSA private exponent."""

    raise NotImplementedError("Implement the toy RSA factorization demonstration")

