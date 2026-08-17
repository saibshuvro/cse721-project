"""Interactive terminal menu for the educational AES-128 implementation."""

from __future__ import annotations

from typing import Callable

from symmetric import aes
from symmetric.aes import AESTrace


def _parse_hex_bytes(text: str, name: str) -> bytes:
    """Convert terminal hexadecimal input to bytes with a focused error."""

    if type(text) is not str:
        raise TypeError(f"{name} must be text, not {type(text).__name__}")

    # Spaces between byte pairs are allowed for readability. Empty input,
    # non-hexadecimal characters, and incomplete final bytes are rejected.
    compact = "".join(text.split())
    if not compact:
        raise ValueError(f"{name} must not be empty")
    if any(character not in "0123456789abcdefABCDEF" for character in compact):
        raise ValueError(f"{name} must contain only hexadecimal digits")
    if len(compact) % 2 != 0:
        raise ValueError(
            f"{name} must contain an even number of hexadecimal digits"
        )

    return bytes.fromhex(compact)


def _parse_key(text: str) -> bytes:
    """Parse one AES-128 key represented by 32 hexadecimal digits."""

    key = _parse_hex_bytes(text, "AES-128 key")
    if len(key) != aes.KEY_SIZE:
        raise ValueError(
            "AES-128 key must be exactly 32 hexadecimal digits (16 bytes)"
        )
    return key


def _parse_block(text: str) -> bytes:
    """Parse one raw AES block represented by 32 hexadecimal digits."""

    block = _parse_hex_bytes(text, "AES block")
    if len(block) != aes.BLOCK_SIZE:
        raise ValueError(
            "AES block must be exactly 32 hexadecimal digits (16 bytes)"
        )
    return block


def _display_key_schedule(key: bytes) -> None:
    """Display the original AES-128 key and K0 through K10."""

    round_keys = aes.expand_key(key)
    print(f"\nAES-128 key (hex): {key.hex().upper()}")
    print(f"Key size: {aes.KEY_SIZE * 8} bits")
    print(f"Rounds: {aes.ROUND_COUNT}")
    print("\nRound-key schedule (encryption order):")
    print("Key  Round key (128-bit hexadecimal)")

    for round_number, round_key in enumerate(round_keys):
        print(f"K{round_number:<2}  {round_key.hex().upper()}")


def _display_block_trace(trace: AESTrace) -> None:
    """Display every transformation state for one raw AES block."""

    print(f"\nDetailed {trace.operation} trace:")
    print("Round  Transformation   State (hex)                         Round key")

    for stage in trace.stages:
        if stage.round_key is None:
            displayed_key = "-"
        else:
            displayed_key = stage.round_key.hex().upper()

        print(
            f"{stage.round_number:>5}  "
            f"{stage.transformation:<15}  "
            f"{stage.state.hex().upper()}  "
            f"{displayed_key}"
        )

    print(f"Final {trace.operation} output: {trace.output.hex().upper()}")


def _run_generate_key() -> None:
    """Generate a random AES-128 key and display all round keys."""

    key = aes.generate_key()
    print("\nGenerated a random AES-128 key.")
    _display_key_schedule(key)
    print("Save this key if you intend to decrypt data encrypted with it.")


def _run_encryption(input_fn: Callable[[str], str]) -> None:
    """Encrypt arbitrary UTF-8 text using an automatically generated key."""

    plaintext_text = input_fn("Enter plaintext: ")
    plaintext = plaintext_text.encode("utf-8")
    key = aes.generate_key()
    ciphertext, traces = aes.encrypt_ecb(plaintext, key)

    print(f"\nPlaintext UTF-8 byte length: {len(plaintext)}")
    print(f"Padded AES blocks encrypted: {len(traces)}")
    print(f"Ciphertext (hex): {ciphertext.hex().upper()}")
    _display_key_schedule(key)
    print("\nSave both the ciphertext and AES-128 key for decryption.")
    print("Security note: this coursework wrapper uses ECB, which leaks patterns.")


def _run_decryption(input_fn: Callable[[str], str]) -> None:
    """Decrypt hexadecimal ECB ciphertext and display recovered UTF-8 text."""

    ciphertext_text = input_fn("Enter ciphertext in hexadecimal: ")
    key_text = input_fn("Enter the 32-hex-digit AES-128 key: ")
    ciphertext = _parse_hex_bytes(ciphertext_text, "Ciphertext")
    key = _parse_key(key_text)

    plaintext, traces = aes.decrypt_ecb(ciphertext, key)
    try:
        plaintext_text = plaintext.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            "decrypted bytes are not valid UTF-8; verify the ciphertext and key"
        ) from error

    print(f"\nCiphertext blocks decrypted: {len(traces)}")
    print(f"Decrypted bytes (hex): {plaintext.hex().upper()}")
    print(f"Decrypted plaintext: {plaintext_text}")
    _display_key_schedule(key)


def _run_key_and_trace_inspection(input_fn: Callable[[str], str]) -> None:
    """Show all round keys and optionally trace one raw AES block."""

    key_text = input_fn("Enter the 32-hex-digit AES-128 key: ")
    key = _parse_key(key_text)
    _display_key_schedule(key)

    print("\nTo inspect one raw 16-byte block, choose E or D.")
    operation = input_fn(
        "Trace operation [E=encrypt, D=decrypt, Enter=keys only]: "
    ).strip().upper()
    if operation == "":
        return
    if operation not in ("E", "D"):
        raise ValueError("trace operation must be E, D, or empty")

    block_text = input_fn("Enter one 32-hex-digit AES block: ")
    block = _parse_block(block_text)
    if operation == "E":
        output, trace = aes.encrypt_block(block, key)
    else:
        output, trace = aes.decrypt_block(block, key)

    print(f"\nInput block: {block.hex().upper()}")
    print(f"Output block: {output.hex().upper()}")
    _display_block_trace(trace)


def run_aes_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run AES-128 operations until the user returns to the main menu."""

    while True:
        print("\nAES-128")
        print("Educational implementation: AES-ECB is insecure for real data.")
        print("1. Generate key and display K0 through K10")
        print("2. Encrypt text with an auto-generated key")
        print("3. Decrypt hexadecimal ciphertext")
        print("4. Display round keys / inspect one-block trace")
        print("5. Return to main menu")

        choice = input_fn("Select an operation: ").strip()

        try:
            if choice == "1":
                _run_generate_key()
            elif choice == "2":
                _run_encryption(input_fn)
            elif choice == "3":
                _run_decryption(input_fn)
            elif choice == "4":
                _run_key_and_trace_inspection(input_fn)
            elif choice == "5":
                return
            else:
                print("\nInvalid selection. Enter a number from 1 to 5.")
        except (TypeError, ValueError) as error:
            print(f"\nError: {error}")
