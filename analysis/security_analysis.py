"""Structured security notes used by the CLI and final report."""

from __future__ import annotations


SECURITY_NOTES: dict[str, tuple[str, ...]] = {
    "substitution": ("Preserves language statistics.", "The full key space is 26!, not CLI-brute-forceable."),
    "double_transposition": ("Preserves character counts.", "Leaks length and can preserve structure."),
    "des": ("Effective key size is 56 bits.", "Exhaustive key search is practical with specialized hardware."),
    "aes-128": ("No practical attack on full AES-128 is known.", "Modes, nonces, padding, and side channels still matter."),
    "rsa": ("Textbook RSA is deterministic and insecure.", "512- and 1024-bit RSA are obsolete for real use."),
    "ecc": ("Small demo curves are trivially breakable.", "Point validation and subgroup checks are required."),
}

