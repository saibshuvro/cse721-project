"""Interactive terminal menu for the Double Transposition cipher."""

from __future__ import annotations

from typing import Callable

from classical import double_transposition
from classical.double_transposition import Grid, TranspositionTrace


def _display_cell(character: str) -> str:
    """Make whitespace visible when printing an intermediate grid."""

    if character == " ":
        return "␠"
    if character == "\t":
        return "\\t"
    if character == "\n":
        return "\\n"
    return character


def _display_grid(title: str, grid: Grid) -> None:
    """Display a rectangular grid without changing its contents."""

    print(title)
    for row in grid:
        print("| " + " | ".join(_display_cell(cell) for cell in row) + " |")


def _display_trace(trace: TranspositionTrace) -> None:
    """Display all intermediate grids with operation-appropriate labels."""

    if not trace.blocks:
        print("\nNo blocks were produced for the empty input.")
        return

    for block_number, block in enumerate(trace.blocks, start=1):
        print(f"\nBlock {block_number}:")
        if trace.operation == "encrypt":
            _display_grid("Input/padded grid:", block.input_grid)
            _display_grid("After row permutation:", block.after_first_step)
            _display_grid("After column permutation:", block.after_second_step)
        else:
            _display_grid("Ciphertext grid:", block.input_grid)
            _display_grid("After inverse column permutation:", block.after_first_step)
            _display_grid("After inverse row permutation:", block.after_second_step)


def _read_keys(input_fn: Callable[[str], str]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Read one-based row/column keys and return validated zero-based keys."""

    print("Enter each key as space-separated positions, for example: 2 1 or 3 1 2")
    row_key_text = input_fn("Enter first permutation key (row order): ")
    column_key_text = input_fn("Enter second permutation key (column order): ")
    row_key = double_transposition.parse_permutation_key(row_key_text, "Row key")
    column_key = double_transposition.parse_permutation_key(column_key_text, "Column key")
    return row_key, column_key


def _display_keys(row_key: tuple[int, ...], column_key: tuple[int, ...]) -> None:
    """Display keys in the same one-based form entered by a terminal user."""

    displayed_row_key = " ".join(str(position + 1) for position in row_key)
    displayed_column_key = " ".join(str(position + 1) for position in column_key)
    print(f"\nFirst permutation key (rows): {displayed_row_key}")
    print(f"Second permutation key (columns): {displayed_column_key}")


def _run_encryption(input_fn: Callable[[str], str]) -> None:
    """Collect encryption input and display ciphertext plus every grid."""

    plaintext = input_fn("Enter plaintext: ")
    row_key, column_key = _read_keys(input_fn)
    ciphertext, trace = double_transposition.encrypt(plaintext, row_key, column_key)

    print(f"\nPlaintext: {plaintext}")
    _display_keys(row_key, column_key)
    print(f"Grid size: {len(row_key)} rows x {len(column_key)} columns")
    print(f"Padding character: {double_transposition.PADDING_CHARACTER}")
    print(f"Padding length: {trace.padding_length}")
    _display_trace(trace)
    print(f"\nCiphertext: {ciphertext}")
    print("Save the keys and padding length; all are required for decryption.")


def _parse_padding_length(text: str) -> int:
    """Parse terminal padding input and provide a focused error message."""

    try:
        return int(text)
    except ValueError as error:
        raise ValueError("Padding length must be an integer") from error


def _run_decryption(input_fn: Callable[[str], str]) -> None:
    """Collect decryption input and display reconstruction plus plaintext."""

    ciphertext = input_fn("Enter ciphertext (include any ~ characters): ")
    row_key, column_key = _read_keys(input_fn)
    padding_text = input_fn("Enter the padding length shown during encryption: ")
    padding_length = _parse_padding_length(padding_text)
    plaintext, trace = double_transposition.decrypt(
        ciphertext,
        row_key,
        column_key,
        padding_length,
    )

    print(f"\nCiphertext: {ciphertext}")
    _display_keys(row_key, column_key)
    print(f"Padding length: {trace.padding_length}")
    _display_trace(trace)
    print(f"\nDecrypted plaintext: {plaintext}")


def _run_frequency_comparison(input_fn: Callable[[str], str]) -> None:
    """Compare A-Z counts and explain the preserved distribution."""

    plaintext = input_fn("Enter the original plaintext: ")
    ciphertext = input_fn("Enter its transposition ciphertext: ")
    comparison = double_transposition.compare_letter_frequencies(plaintext, ciphertext)

    print("\nLetter-frequency comparison:")
    print("Letter  Plaintext  Ciphertext  Match")
    for letter, (plaintext_count, ciphertext_count) in comparison.items():
        matches = "Yes" if plaintext_count == ciphertext_count else "No"
        print(f"{letter:^6}  {plaintext_count:>9}  {ciphertext_count:>10}  {matches:>5}")

    frequencies_match = all(
        plaintext_count == ciphertext_count
        for plaintext_count, ciphertext_count in comparison.values()
    )
    if frequencies_match:
        print("\nResult: A-Z frequencies are preserved.")
        print(
            "A transposition changes positions, not letters; frequency analysis "
            "alone does not reveal the row and column keys."
        )
    else:
        print("\nResult: Frequencies do not match. Verify that these texts form a matching pair.")


def run_double_transposition_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run Double Transposition operations until returning to the main menu."""

    while True:
        print("\nDouble Transposition Cipher")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Frequency comparison")
        print("4. Return to main menu")

        choice = input_fn("Select an operation: ").strip()

        try:
            if choice == "1":
                _run_encryption(input_fn)
            elif choice == "2":
                _run_decryption(input_fn)
            elif choice == "3":
                _run_frequency_comparison(input_fn)
            elif choice == "4":
                return
            else:
                print("\nInvalid selection. Enter a number from 1 to 4.")
        except (TypeError, ValueError) as error:
            print(f"\nError: {error}")

