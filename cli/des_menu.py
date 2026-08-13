"""Interactive terminal menu for the educational DES implementation."""

from __future__ import annotations

from typing import Callable

from symmetric import des
from symmetric.des import DESTrace


def _parse_hex_bytes(text: str, name: str) -> bytes:
    """Convert terminal hexadecimal input to bytes with a focused error."""

    if type(text) is not str:
        raise TypeError(f"{name} must be text, not {type(text).__name__}")

    # Permit spaces between byte pairs for readability, but do not silently
    # accept an empty value or an incomplete final byte.
    compact = "".join(text.split())
    if not compact:
        raise ValueError(f"{name} must not be empty")
    if any(character not in "0123456789abcdefABCDEF" for character in compact):
        raise ValueError(f"{name} must contain only hexadecimal digits")
    if len(compact) % 2 != 0:
        raise ValueError(f"{name} must contain an even number of hexadecimal digits")

    return bytes.fromhex(compact)


def _parse_key(text: str) -> bytes:
    """Parse one DES key represented by exactly 16 hexadecimal digits."""

    key = _parse_hex_bytes(text, "DES key")
    if len(key) != des.KEY_SIZE:
        raise ValueError("DES key must be exactly 16 hexadecimal digits (8 bytes)")
    return key


def _parse_block(text: str) -> bytes:
    """Parse one raw DES block represented by 16 hexadecimal digits."""

    block = _parse_hex_bytes(text, "DES block")
    if len(block) != des.BLOCK_SIZE:
        raise ValueError("DES block must be exactly 16 hexadecimal digits (8 bytes)")
    return block


def _display_key_schedule(key: bytes) -> None:
    """Display the supplied key and all K1 through K16 values."""

    schedule = des.build_key_schedule(key)
    print(f"\nDES key (hex): {key.hex().upper()}")
    print(f"Effective key size: {des.EFFECTIVE_KEY_BITS} bits")
    print(f"Odd parity in every key byte: {'Yes' if des.has_odd_parity(key) else 'No'}")
    print(f"Weak or semi-weak key: {'Yes' if des.is_weak_key(key) else 'No'}")
    print("\nRound-key schedule (encryption order):")
    print("Round  Shift  C_i      D_i      K_i")
    for round_state in schedule:
        print(
            f"{round_state.round_number:>5}  "
            f"{round_state.shift:>5}  "
            f"{round_state.left_half:07X}  "
            f"{round_state.right_half:07X}  "
            f"{round_state.subkey:012X}"
        )


def _display_block_trace(trace: DESTrace) -> None:
    """Display every intermediate value for one raw DES block."""

    print(f"\nDetailed {trace.operation} trace:")
    print(f"After initial permutation: {trace.initial_permutation:016X}")
    print(
        "Round  L input   R input   Subkey       E(R)          "
        "E(R) XOR K    S-box     P output  L output  R output"
    )
    for round_trace in trace.rounds:
        print(
            f"{round_trace.round_number:>5}  "
            f"{round_trace.left_input:08X}  "
            f"{round_trace.right_input:08X}  "
            f"{round_trace.subkey:012X}  "
            f"{round_trace.expanded_right:012X}  "
            f"{round_trace.mixed_with_key:012X}  "
            f"{round_trace.sbox_output:08X}  "
            f"{round_trace.p_output:08X}  "
            f"{round_trace.left_output:08X}  "
            f"{round_trace.right_output:08X}"
        )
    print(f"Preoutput R16 || L16: {trace.preoutput:016X}")
    print(f"After final permutation: {trace.output:016X}")


def _run_generate_key() -> None:
    """Generate a suitable educational DES key and show its round keys."""

    key = des.generate_key()
    print("\nGenerated a random odd-parity, non-weak DES key.")
    _display_key_schedule(key)
    print("Save this key if you intend to decrypt data encrypted with it.")


def _run_encryption(input_fn: Callable[[str], str]) -> None:
    """Encrypt arbitrary UTF-8 text using an automatically generated key."""

    plaintext_text = input_fn("Enter plaintext: ")
    plaintext = plaintext_text.encode("utf-8")
    key = des.generate_key()
    ciphertext, traces = des.encrypt_ecb(plaintext, key)

    print(f"\nPlaintext UTF-8 byte length: {len(plaintext)}")
    print(f"Padded DES blocks encrypted: {len(traces)}")
    print(f"Ciphertext (hex): {ciphertext.hex().upper()}")
    _display_key_schedule(key)
    print("\nSave both the ciphertext and DES key for decryption.")
    print("Security note: this coursework wrapper uses ECB, which leaks patterns.")


def _run_decryption(input_fn: Callable[[str], str]) -> None:
    """Decrypt hexadecimal ECB ciphertext and display recovered UTF-8 text."""

    ciphertext_text = input_fn("Enter ciphertext in hexadecimal: ")
    key_text = input_fn("Enter the 16-hex-digit DES key: ")
    ciphertext = _parse_hex_bytes(ciphertext_text, "Ciphertext")
    key = _parse_key(key_text)

    plaintext, traces = des.decrypt_ecb(ciphertext, key)
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
    """Show a key schedule and optionally trace one raw DES block."""

    key_text = input_fn("Enter the 16-hex-digit DES key: ")
    key = _parse_key(key_text)
    _display_key_schedule(key)

    print("\nTo inspect one block, choose E or D.")
    operation = input_fn(
        "Trace operation [E=encrypt, D=decrypt, Enter=keys only]: "
    ).strip().upper()
    if operation == "":
        return
    if operation not in ("E", "D"):
        raise ValueError("trace operation must be E, D, or empty")

    block_text = input_fn("Enter one 16-hex-digit DES block: ")
    block = _parse_block(block_text)
    if operation == "E":
        output, trace = des.encrypt_block(block, key)
    else:
        output, trace = des.decrypt_block(block, key)

    print(f"\nInput block: {block.hex().upper()}")
    print(f"Output block: {output.hex().upper()}")
    _display_block_trace(trace)


def run_des_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run DES operations until the user returns to the main menu."""

    while True:
        print("\nDES")
        print("Educational implementation: single DES and ECB are insecure.")
        print("1. Generate key and display all round keys")
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
