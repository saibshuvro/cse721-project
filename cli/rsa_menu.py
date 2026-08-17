"""Interactive terminal menu for the educational textbook RSA implementation."""

from __future__ import annotations

from time import perf_counter_ns
from typing import Callable

from public_key import factorization, rsa
from public_key.rsa import KeyPair


# A deterministic small RSA example keeps the attack bounded and easy to
# verify. It is separate from every normal key generated in the submenu.
TOY_ATTACK_MODULUS = 3_233
TOY_ATTACK_PUBLIC_EXPONENT = 17
TOY_ATTACK_CIPHERTEXT = 2_790
TOY_ATTACK_MAX_DIVISOR = 100


def _parse_key_size(text: str) -> int:
    """Parse one of the key sizes explicitly requested by the assignment."""

    if not isinstance(text, str):
        raise TypeError("Key size must be text")

    try:
        key_size = int(text.strip())
    except ValueError as error:
        raise ValueError("Key size must be 512 or 1024 bits") from error

    if key_size not in rsa.COURSEWORK_KEY_SIZES:
        raise ValueError("Key size must be 512 or 1024 bits")

    return key_size


def _parse_ciphertext_blocks(text: str) -> list[int]:
    """Parse space/comma-separated decimal or ``0x`` hexadecimal blocks.

    An empty line represents the empty ciphertext list, which is the encrypted
    form of an empty plaintext string in this coursework wrapper.
    """

    if not isinstance(text, str):
        raise TypeError("Ciphertext blocks must be text")

    tokens = text.replace(",", " ").split()
    blocks: list[int] = []

    for index, token in enumerate(tokens, start=1):
        try:
            if token.lower().startswith("0x"):
                hexadecimal_digits = token[2:]
                if not hexadecimal_digits:
                    raise ValueError
                block = int(hexadecimal_digits, 16)
            else:
                # Decimal input is deliberately strict. A leading minus sign,
                # decimal point, or other character should not be accepted.
                if not token.isdecimal():
                    raise ValueError
                block = int(token, 10)
        except ValueError as error:
            raise ValueError(
                f"Ciphertext block {index} must be a decimal integer or start with 0x"
            ) from error

        blocks.append(block)

    return blocks


def _display_keypair(keypair: KeyPair) -> None:
    """Display the assignment's public/private key outputs without p or q."""

    print(f"\nGenerated RSA modulus size: {keypair.modulus_bits} bits")
    print("\nPublic key (n, e):")
    print(f"n (decimal): {keypair.public.modulus}")
    print(f"n (hex): 0x{keypair.public.modulus:X}")
    print(f"e: {keypair.public.exponent}")

    print("\nPrivate key (n, d):")
    print(f"n (decimal): {keypair.private.modulus}")
    print(f"d: {keypair.private.exponent}")
    print("Keep d, p, and q secret. The primes are intentionally not displayed.")


def _require_current_keypair(keypair: KeyPair | None) -> KeyPair:
    """Return the active key pair or provide a focused workflow error."""

    if keypair is None:
        raise ValueError("Generate a key pair with option 1 first")
    return keypair


def _run_generate_keys(input_fn: Callable[[str], str]) -> KeyPair:
    """Generate an assignment-size RSA key pair and display both keys."""

    print("\nAvailable coursework key sizes: 512 or 1024 bits.")
    key_size_text = input_fn("Enter RSA key size in bits: ")
    key_size = _parse_key_size(key_size_text)

    print(f"Generating a random {key_size}-bit RSA key pair...")
    start_ns = perf_counter_ns()
    keypair = rsa.generate_keypair(key_size)
    elapsed_ns = perf_counter_ns() - start_ns

    _display_keypair(keypair)
    print(f"Key-generation time: {elapsed_ns / 1_000_000:.3f} ms")
    print("This key pair remains active until you return to the main menu.")
    return keypair


def _run_encryption(
    input_fn: Callable[[str], str],
    keypair: KeyPair | None,
) -> None:
    """Encrypt UTF-8 text with the active public key and show both formats."""

    active_keypair = _require_current_keypair(keypair)
    plaintext = input_fn("Enter plaintext: ")
    ciphertext = rsa.encrypt_text(plaintext, active_keypair.public)

    print(f"\nPlaintext UTF-8 byte length: {len(plaintext.encode('utf-8'))}")
    print(f"RSA ciphertext block count: {len(ciphertext)}")

    if not ciphertext:
        print("Ciphertext blocks: (empty list)")
    else:
        print("\nCiphertext blocks:")
        print("Block  Decimal integer  Hexadecimal")
        for index, block in enumerate(ciphertext, start=1):
            print(f"{index:>5}  {block}  0x{block:X}")

    print("\nSave the ciphertext blocks in order for decryption.")
    print("Security note: textbook RSA is deterministic and does not implement OAEP.")


def _run_decryption(
    input_fn: Callable[[str], str],
    keypair: KeyPair | None,
) -> None:
    """Decrypt decimal/hexadecimal blocks using the active private key."""

    active_keypair = _require_current_keypair(keypair)
    print("Enter blocks in order, separated by spaces or commas.")
    print("Each block may be decimal or hexadecimal beginning with 0x.")
    ciphertext_text = input_fn("Enter ciphertext blocks: ")
    ciphertext = _parse_ciphertext_blocks(ciphertext_text)
    plaintext = rsa.decrypt_text(ciphertext, active_keypair.private)

    print(f"\nCiphertext blocks decrypted: {len(ciphertext)}")
    print(f"Decrypted plaintext: {plaintext}")


def _run_factorization_demo() -> None:
    """Factor the fixed toy modulus and reconstruct its private exponent."""

    print("\nToy RSA factorization demonstration")
    print("This attack is deliberately isolated from the normal generated key.")
    print(f"Public modulus n: {TOY_ATTACK_MODULUS}")
    print(f"Public exponent e: {TOY_ATTACK_PUBLIC_EXPONENT}")
    print(f"Known example ciphertext: {TOY_ATTACK_CIPHERTEXT}")
    print(f"Trial-divisor limit: {TOY_ATTACK_MAX_DIVISOR}")

    start_ns = perf_counter_ns()
    factors = factorization.trial_division(
        TOY_ATTACK_MODULUS,
        max_divisor=TOY_ATTACK_MAX_DIVISOR,
    )
    recovered_exponent = factorization.recover_private_exponent(
        modulus=TOY_ATTACK_MODULUS,
        public_exponent=TOY_ATTACK_PUBLIC_EXPONENT,
        max_divisor=TOY_ATTACK_MAX_DIVISOR,
    )
    elapsed_ns = perf_counter_ns() - start_ns

    if factors is None:
        # recover_private_exponent() already raises in this case. This branch
        # narrows the type and guards against future changes to that function.
        raise ValueError("Toy factors were not found within the configured bound")

    prime_p, prime_q = factors
    totient = (prime_p - 1) * (prime_q - 1)
    recovered_key = rsa.PrivateKey(
        exponent=recovered_exponent,
        modulus=TOY_ATTACK_MODULUS,
    )
    recovered_message = rsa.decrypt_int(TOY_ATTACK_CIPHERTEXT, recovered_key)

    print(f"\nRecovered factors: p={prime_p}, q={prime_q}")
    print(f"Reconstructed phi(n): {totient}")
    print(f"Recovered private exponent d: {recovered_exponent}")
    print(f"Decrypted example integer: {recovered_message}")
    print(f"Attack demonstration time: {elapsed_ns / 1_000_000:.3f} ms")
    print("Result: factoring n exposed enough information to reconstruct d.")
    print("Trial division is not practical against the normal 512/1024-bit key.")


def run_rsa_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run RSA operations until the user returns to the main menu."""

    current_keypair: KeyPair | None = None

    while True:
        print("\nRSA")
        print("Educational textbook RSA: deterministic, unpadded, and insecure.")
        print("The assignment's 512/1024-bit sizes are obsolete for real use.")
        print("1. Generate keys")
        print("2. Encrypt plaintext")
        print("3. Decrypt integer/hex ciphertext blocks")
        print("4. Run toy factorization demonstration")
        print("5. Return to main menu")

        choice = input_fn("Select an operation: ").strip()

        try:
            if choice == "1":
                current_keypair = _run_generate_keys(input_fn)
            elif choice == "2":
                _run_encryption(input_fn, current_keypair)
            elif choice == "3":
                _run_decryption(input_fn, current_keypair)
            elif choice == "4":
                _run_factorization_demo()
            elif choice == "5":
                return
            else:
                print("\nInvalid selection. Enter a number from 1 to 5.")
        except (TypeError, ValueError) as error:
            print(f"\nError: {error}")
