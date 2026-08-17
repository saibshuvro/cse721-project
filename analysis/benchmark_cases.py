"""Prepared performance cases for all six coursework components.

This module connects the generic timer in :mod:`analysis.performance` to the
implemented algorithms. Case construction is cheap: expensive prerequisites,
such as RSA key generation for an encryption benchmark, run only when that
case's ``prepare`` function is called and remain outside the measured region.
"""

from __future__ import annotations

from functools import partial
from math import factorial
from typing import Callable

from analysis.performance import (
    BenchmarkCase,
    OperationPreparation,
    PreparedOperation,
)
from classical import double_transposition, frequency_analysis, substitution
from public_key import ecdh, factorization, rsa
from public_key.ecc import DEFAULT_CURVE
from symmetric import aes, des


DEFAULT_MESSAGE_SIZES = (16, 64, 256, 1024)
DEFAULT_RSA_MESSAGE_SIZES = (16, 64, 256)
DEFAULT_REDUCED_ALPHABET_SIZES = (3, 4, 5, 6)
DEFAULT_REPETITIONS = 30
DEFAULT_SLOW_REPETITIONS = 5
DEFAULT_WARMUPS = 3
DEFAULT_SLOW_WARMUPS = 1
REDUCED_ATTACK_MESSAGE_SIZE = 64

SUBSTITUTION_KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"
TRANSPOSITION_ROW_KEY = (2, 0, 3, 1)
TRANSPOSITION_COLUMN_KEY = (1, 3, 0, 2)
DES_KEY = bytes.fromhex("133457799BBCDFF1")
AES_128_KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

# These semiprimes are intentionally tiny. They demonstrate how attack cost
# grows without attempting to factor normal coursework RSA keys.
TOY_RSA_MODULI = (3_233, 1_022_117)


def _validate_positive_sizes(
    values: tuple[int, ...],
    name: str,
) -> tuple[int, ...]:
    """Require a non-empty tuple of distinct positive integer sizes."""

    if type(values) is not tuple:
        raise TypeError(f"{name} must be a tuple")
    if not values:
        raise ValueError(f"{name} must not be empty")

    for index, value in enumerate(values):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} item {index} must be an integer")
        if value < 1:
            raise ValueError(f"{name} item {index} must be positive")

    if len(set(values)) != len(values):
        raise ValueError(f"{name} must not contain duplicate sizes")
    return values


def _validate_count(value: int, name: str, minimum: int) -> int:
    """Validate a repetition or warm-up count."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _ascii_message(length: int) -> str:
    """Return deterministic ASCII text of exactly ``length`` characters."""

    source = (
        "Cryptography compares algorithms using fixed, repeatable messages. "
    )
    repetitions = (length + len(source) - 1) // len(source)
    return (source * repetitions)[:length]


def _static_preparation(
    function: Callable[..., object],
    *arguments: object,
) -> OperationPreparation:
    """Return preparation that binds already prepared operation arguments."""

    def prepare() -> PreparedOperation:
        return partial(function, *arguments)

    return prepare


def _substitution_decryption_preparation(
    plaintext: str,
) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        ciphertext = substitution.encrypt(plaintext, SUBSTITUTION_KEY)
        return partial(substitution.decrypt, ciphertext, SUBSTITUTION_KEY)

    return prepare


def _run_substitution_frequency_analysis(ciphertext: str) -> tuple[object, ...]:
    """Perform the same non-I/O analysis stages used by the submenu."""

    counts = frequency_analysis.letter_counts(ciphertext)
    percentages = frequency_analysis.letter_percentages(ciphertext)
    ranking = frequency_analysis.ranked_letters(ciphertext)
    mapping = frequency_analysis.suggest_english_mapping(ciphertext)
    preview = frequency_analysis.apply_partial_mapping(ciphertext, mapping)
    return counts, percentages, ranking, mapping, preview


def _substitution_analysis_preparation(
    plaintext: str,
) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        ciphertext = substitution.encrypt(plaintext, SUBSTITUTION_KEY)
        return partial(_run_substitution_frequency_analysis, ciphertext)

    return prepare


def _reduced_attack_preparation(alphabet: str) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        plaintext = (alphabet * REDUCED_ATTACK_MESSAGE_SIZE)[
            :REDUCED_ATTACK_MESSAGE_SIZE
        ]
        shifted_alphabet = alphabet[1:] + alphabet[:1]
        ciphertext = plaintext.translate(str.maketrans(alphabet, shifted_alphabet))
        return partial(substitution.brute_force_reduced, ciphertext, alphabet)

    return prepare


def _transposition_decryption_preparation(
    plaintext: str,
) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        ciphertext, trace = double_transposition.encrypt(
            plaintext,
            TRANSPOSITION_ROW_KEY,
            TRANSPOSITION_COLUMN_KEY,
        )
        return partial(
            double_transposition.decrypt,
            ciphertext,
            TRANSPOSITION_ROW_KEY,
            TRANSPOSITION_COLUMN_KEY,
            trace.padding_length,
        )

    return prepare


def _transposition_analysis_preparation(
    plaintext: str,
) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        ciphertext, _ = double_transposition.encrypt(
            plaintext,
            TRANSPOSITION_ROW_KEY,
            TRANSPOSITION_COLUMN_KEY,
        )
        return partial(
            double_transposition.compare_letter_frequencies,
            plaintext,
            ciphertext,
        )

    return prepare


def _des_decryption_preparation(plaintext: bytes) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        ciphertext, _ = des.encrypt_ecb(plaintext, DES_KEY)
        return partial(des.decrypt_ecb, ciphertext, DES_KEY)

    return prepare


def _aes_decryption_preparation(plaintext: bytes) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        ciphertext, _ = aes.encrypt_ecb(plaintext, AES_128_KEY)
        return partial(aes.decrypt_ecb, ciphertext, AES_128_KEY)

    return prepare


def _rsa_encryption_preparation(
    key_bits: int,
    plaintext: str,
) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        keypair = rsa.generate_keypair(key_bits)
        return partial(rsa.encrypt_text, plaintext, keypair.public)

    return prepare


def _rsa_decryption_preparation(
    key_bits: int,
    plaintext: str,
) -> OperationPreparation:
    def prepare() -> PreparedOperation:
        keypair = rsa.generate_keypair(key_bits)
        ciphertext = rsa.encrypt_text(plaintext, keypair.public)
        return partial(rsa.decrypt_text, ciphertext, keypair.private)

    return prepare


def _ecdh_shared_point_preparation() -> OperationPreparation:
    def prepare() -> PreparedOperation:
        alice_private = 5
        bob_private = 7
        bob_public = ecdh.public_key(DEFAULT_CURVE, bob_private)
        return partial(
            ecdh.shared_point,
            DEFAULT_CURVE,
            alice_private,
            bob_public,
        )

    return prepare


def build_benchmark_cases(
    message_sizes: tuple[int, ...] = DEFAULT_MESSAGE_SIZES,
    rsa_message_sizes: tuple[int, ...] = DEFAULT_RSA_MESSAGE_SIZES,
    rsa_key_sizes: tuple[int, ...] = rsa.COURSEWORK_KEY_SIZES,
    reduced_alphabet_sizes: tuple[int, ...] = DEFAULT_REDUCED_ALPHABET_SIZES,
    repetitions: int = DEFAULT_REPETITIONS,
    slow_repetitions: int = DEFAULT_SLOW_REPETITIONS,
) -> tuple[BenchmarkCase, ...]:
    """Return lazily prepared benchmark cases for all project components."""

    message_sizes = _validate_positive_sizes(message_sizes, "Message sizes")
    rsa_message_sizes = _validate_positive_sizes(
        rsa_message_sizes,
        "RSA message sizes",
    )
    rsa_key_sizes = _validate_positive_sizes(rsa_key_sizes, "RSA key sizes")
    reduced_alphabet_sizes = _validate_positive_sizes(
        reduced_alphabet_sizes,
        "Reduced alphabet sizes",
    )
    repetitions = _validate_count(repetitions, "Repetitions", minimum=1)
    slow_repetitions = _validate_count(
        slow_repetitions,
        "Slow repetitions",
        minimum=1,
    )

    for key_bits in rsa_key_sizes:
        if key_bits < rsa.MINIMUM_EDUCATIONAL_KEY_BITS or key_bits % 2 != 0:
            raise ValueError(
                "RSA key sizes must be even and at least "
                f"{rsa.MINIMUM_EDUCATIONAL_KEY_BITS} bits"
            )

    for alphabet_size in reduced_alphabet_sizes:
        if alphabet_size < 2 or alphabet_size > 8:
            raise ValueError("Reduced alphabet sizes must be in the interval 2..8")

    cases: list[BenchmarkCase] = []

    # Classical substitution cases.
    for message_size in message_sizes:
        plaintext = _ascii_message(message_size)
        cases.extend(
            (
                BenchmarkCase(
                    algorithm="Substitution",
                    operation="encrypt",
                    input_size=message_size,
                    input_unit="characters",
                    key_parameters="26-letter monoalphabetic permutation",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_static_preparation(
                        substitution.encrypt,
                        plaintext,
                        SUBSTITUTION_KEY,
                    ),
                ),
                BenchmarkCase(
                    algorithm="Substitution",
                    operation="decrypt",
                    input_size=message_size,
                    input_unit="characters",
                    key_parameters="26-letter monoalphabetic permutation",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_substitution_decryption_preparation(plaintext),
                ),
                BenchmarkCase(
                    algorithm="Substitution",
                    operation="frequency analysis",
                    input_size=message_size,
                    input_unit="characters",
                    key_parameters="English frequency-rank heuristic",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_substitution_analysis_preparation(plaintext),
                ),
            )
        )

    for alphabet_size in reduced_alphabet_sizes:
        alphabet = substitution.ALPHABET[:alphabet_size]
        cases.append(
            BenchmarkCase(
                algorithm="Substitution",
                operation="reduced brute-force attack",
                input_size=REDUCED_ATTACK_MESSAGE_SIZE,
                input_unit="characters",
                key_parameters=(
                    f"alphabet size {alphabet_size}; "
                    f"{factorial(alphabet_size)} candidate keys"
                ),
                repetitions=slow_repetitions,
                warmups=DEFAULT_SLOW_WARMUPS,
                prepare=_reduced_attack_preparation(alphabet),
            )
        )

    # Double transposition cases use the same 4x4 grid for every message size.
    transposition_parameters = "4x4 grid; row and column permutation keys"
    for message_size in message_sizes:
        plaintext = _ascii_message(message_size)
        cases.extend(
            (
                BenchmarkCase(
                    algorithm="Double Transposition",
                    operation="encrypt",
                    input_size=message_size,
                    input_unit="characters",
                    key_parameters=transposition_parameters,
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_static_preparation(
                        double_transposition.encrypt,
                        plaintext,
                        TRANSPOSITION_ROW_KEY,
                        TRANSPOSITION_COLUMN_KEY,
                    ),
                ),
                BenchmarkCase(
                    algorithm="Double Transposition",
                    operation="decrypt",
                    input_size=message_size,
                    input_unit="characters",
                    key_parameters=transposition_parameters,
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_transposition_decryption_preparation(plaintext),
                ),
                BenchmarkCase(
                    algorithm="Double Transposition",
                    operation="frequency comparison",
                    input_size=message_size,
                    input_unit="characters",
                    key_parameters=transposition_parameters,
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_transposition_analysis_preparation(plaintext),
                ),
            )
        )

    # Symmetric key generation is measured separately from message operations.
    cases.append(
        BenchmarkCase(
            algorithm="DES",
            operation="key generation",
            input_size=None,
            input_unit=None,
            key_parameters="64 supplied bits; 56 effective key bits",
            repetitions=repetitions,
            warmups=DEFAULT_WARMUPS,
            prepare=_static_preparation(des.generate_key),
        )
    )
    cases.append(
        BenchmarkCase(
            algorithm="AES-128",
            operation="key generation",
            input_size=None,
            input_unit=None,
            key_parameters="128-bit key",
            repetitions=repetitions,
            warmups=DEFAULT_WARMUPS,
            prepare=_static_preparation(aes.generate_key),
        )
    )

    for message_size in message_sizes:
        plaintext_bytes = _ascii_message(message_size).encode("ascii")
        cases.extend(
            (
                BenchmarkCase(
                    algorithm="DES",
                    operation="ECB encrypt",
                    input_size=message_size,
                    input_unit="bytes",
                    key_parameters="56 effective key bits; 8-byte blocks",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_static_preparation(
                        des.encrypt_ecb,
                        plaintext_bytes,
                        DES_KEY,
                    ),
                ),
                BenchmarkCase(
                    algorithm="DES",
                    operation="ECB decrypt",
                    input_size=message_size,
                    input_unit="plaintext bytes",
                    key_parameters="56 effective key bits; 8-byte blocks",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_des_decryption_preparation(plaintext_bytes),
                ),
                BenchmarkCase(
                    algorithm="AES-128",
                    operation="ECB encrypt",
                    input_size=message_size,
                    input_unit="bytes",
                    key_parameters="128-bit key; 16-byte blocks",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_static_preparation(
                        aes.encrypt_ecb,
                        plaintext_bytes,
                        AES_128_KEY,
                    ),
                ),
                BenchmarkCase(
                    algorithm="AES-128",
                    operation="ECB decrypt",
                    input_size=message_size,
                    input_unit="plaintext bytes",
                    key_parameters="128-bit key; 16-byte blocks",
                    repetitions=repetitions,
                    warmups=DEFAULT_WARMUPS,
                    prepare=_aes_decryption_preparation(plaintext_bytes),
                ),
            )
        )

    # RSA key size affects key generation and the modular operations. Each
    # encryption/decryption preparation creates one key pair outside timing.
    for key_bits in rsa_key_sizes:
        rsa_parameters = f"{key_bits}-bit educational textbook RSA"
        cases.append(
            BenchmarkCase(
                algorithm="RSA",
                operation="key generation",
                input_size=None,
                input_unit=None,
                key_parameters=rsa_parameters,
                repetitions=slow_repetitions,
                warmups=DEFAULT_SLOW_WARMUPS,
                prepare=_static_preparation(rsa.generate_keypair, key_bits),
            )
        )

        for message_size in rsa_message_sizes:
            plaintext = _ascii_message(message_size)
            cases.extend(
                (
                    BenchmarkCase(
                        algorithm="RSA",
                        operation="text encrypt",
                        input_size=message_size,
                        input_unit="UTF-8 bytes",
                        key_parameters=rsa_parameters,
                        repetitions=repetitions,
                        warmups=DEFAULT_WARMUPS,
                        prepare=_rsa_encryption_preparation(key_bits, plaintext),
                    ),
                    BenchmarkCase(
                        algorithm="RSA",
                        operation="text decrypt",
                        input_size=message_size,
                        input_unit="plaintext UTF-8 bytes",
                        key_parameters=rsa_parameters,
                        repetitions=repetitions,
                        warmups=DEFAULT_WARMUPS,
                        prepare=_rsa_decryption_preparation(key_bits, plaintext),
                    ),
                )
            )

    for modulus in TOY_RSA_MODULI:
        cases.append(
            BenchmarkCase(
                algorithm="RSA",
                operation="factorization attack",
                input_size=modulus.bit_length(),
                input_unit="modulus bits",
                key_parameters=f"toy modulus n={modulus}; e=65537",
                repetitions=slow_repetitions,
                warmups=DEFAULT_SLOW_WARMUPS,
                prepare=_static_preparation(
                    factorization.recover_private_exponent,
                    modulus,
                    rsa.DEFAULT_PUBLIC_EXPONENT,
                    2_000,
                ),
            )
        )

    # ECC is key agreement rather than message encryption. Its operations use
    # the deliberately tiny p=17, n=19 curve required for visible inspection.
    curve_parameters = "p=17, a=2, b=2, G=(5,1), n=19"
    cases.extend(
        (
            BenchmarkCase(
                algorithm="ECC/ECDH",
                operation="private-key generation",
                input_size=None,
                input_unit=None,
                key_parameters=curve_parameters,
                repetitions=repetitions,
                warmups=DEFAULT_WARMUPS,
                prepare=_static_preparation(
                    ecdh.generate_private_key,
                    DEFAULT_CURVE,
                ),
            ),
            BenchmarkCase(
                algorithm="ECC/ECDH",
                operation="public-key derivation",
                input_size=None,
                input_unit=None,
                key_parameters=curve_parameters,
                repetitions=repetitions,
                warmups=DEFAULT_WARMUPS,
                prepare=_static_preparation(ecdh.public_key, DEFAULT_CURVE, 5),
            ),
            BenchmarkCase(
                algorithm="ECC/ECDH",
                operation="shared-point derivation",
                input_size=None,
                input_unit=None,
                key_parameters=curve_parameters,
                repetitions=repetitions,
                warmups=DEFAULT_WARMUPS,
                prepare=_ecdh_shared_point_preparation(),
            ),
            BenchmarkCase(
                algorithm="ECC/ECDH",
                operation="point enumeration",
                input_size=DEFAULT_CURVE.prime,
                input_unit="field elements per axis",
                key_parameters=curve_parameters,
                repetitions=repetitions,
                warmups=DEFAULT_WARMUPS,
                prepare=_static_preparation(DEFAULT_CURVE.enumerate_points),
            ),
        )
    )

    return tuple(cases)
