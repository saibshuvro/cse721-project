"""Double transposition with explicit row and column permutations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TranspositionTrace:
    """Values required for explaining a double-transposition operation."""

    input_grid: tuple[tuple[str, ...], ...]
    after_rows: tuple[tuple[str, ...], ...]
    after_columns: tuple[tuple[str, ...], ...]
    padding_length: int


def encrypt(
    plaintext: str,
    row_key: tuple[int, ...],
    column_key: tuple[int, ...],
) -> tuple[str, TranspositionTrace]:
    """Apply row permutation followed by column permutation."""

    raise NotImplementedError("Implement double-transposition encryption")


def decrypt(
    ciphertext: str,
    row_key: tuple[int, ...],
    column_key: tuple[int, ...],
    padding_length: int,
) -> tuple[str, TranspositionTrace]:
    """Apply inverse permutations and remove only recorded padding."""

    raise NotImplementedError("Implement double-transposition decryption")

