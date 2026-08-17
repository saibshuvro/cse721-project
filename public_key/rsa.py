"""Guided, from-scratch textbook RSA implementation template.

Coursework scope
----------------
This module will implement:

* Euclid and the extended Euclidean algorithm;
* square-and-multiply modular exponentiation;
* Miller-Rabin probable-prime testing;
* random two-prime RSA key generation;
* the RSA integer encryption/decryption primitives; and
* reversible UTF-8 blocking for a terminal demonstration.

The text wrapper is deliberately *textbook RSA*. It does not implement OAEP,
is deterministic, and must not be used to protect real data. The custom marker
byte used by the wrapper preserves block boundaries and zero bytes; it is an
encoding device, not secure cryptographic padding.

Python big integers and the ``secrets`` module are permitted by the assignment.
Core number-theory operations are still implemented here rather than delegated
to a cryptographic library. Complete the TODO functions in the order described
in ``docs/rsa-guide.md``. Core functions must not call ``input`` or ``print``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass


DEFAULT_PUBLIC_EXPONENT = 65_537
DEFAULT_MILLER_RABIN_ROUNDS = 40
MINIMUM_EDUCATIONAL_KEY_BITS = 32
COURSEWORK_KEY_SIZES = (512, 1024)
TEXT_BLOCK_MARKER = 0x01

# Checking a few small primes first rejects many composite candidates cheaply.
# Miller-Rabin still performs the real probable-prime test for other values.
SMALL_PRIMES = (
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
)


@dataclass(frozen=True)
class PublicKey:
    """Simple RSA public key containing public exponent ``e`` and modulus ``n``."""

    exponent: int
    modulus: int


@dataclass(frozen=True)
class PrivateKey:
    """Simple RSA private key containing private exponent ``d`` and modulus ``n``."""

    exponent: int
    modulus: int


@dataclass(frozen=True)
class KeyPair:
    """RSA keys plus secret generation values retained for coursework inspection.

    ``prime_p`` and ``prime_q`` must be treated as private. They are retained so
    tests and the terminal demonstration can explain why key generation works;
    a public-key export must never include them.
    """

    public: PublicKey
    private: PrivateKey
    prime_p: int
    prime_q: int

    @property
    def modulus_bits(self) -> int:
        """Return the actual bit length of the shared modulus."""

        return self.public.modulus.bit_length()


def _require_integer(
    value: int,
    name: str,
    minimum: int | None = None,
) -> int:
    """Validate an exact integer, optionally enforcing an inclusive minimum.

    TODO(student):
        1. Reject non-integers and booleans with ``TypeError``.
        2. If ``minimum`` is not ``None``, reject smaller values.
        3. Return the validated integer.
    """

    # ``bool`` is a subclass of ``int`` in Python. Check it separately so
    # values such as True are not silently accepted as the integer 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")

    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")

    return value


def greatest_common_divisor(left: int, right: int) -> int:
    """Return ``gcd(left, right)`` using Euclid's remainder algorithm.

    TODO(student): repeatedly replace ``(a, b)`` with ``(b, a % b)`` until
    ``b`` is zero. Return a non-negative GCD and handle zero inputs cleanly.
    """

    # GCD is defined as a non-negative value, so normalize signs before
    # applying Euclid's remainder algorithm.
    current = abs(_require_integer(left, "Left value"))
    remainder = abs(_require_integer(right, "Right value"))

    while remainder != 0:
        current, remainder = remainder, current % remainder

    return current


def extended_gcd(left: int, right: int) -> tuple[int, int, int]:
    """Return ``(gcd, x, y)`` satisfying ``left*x + right*y == gcd``.

    TODO(student): implement the iterative extended Euclidean algorithm while
    tracking the coefficient pair for each remainder. Normalize the returned
    GCD to be non-negative.
    """

    validated_left = _require_integer(left, "Left value")
    validated_right = _require_integer(right, "Right value")

    # Work with non-negative remainders. old_x/current_x track the
    # coefficient of abs(left), while old_y/current_y track abs(right).
    old_remainder, current_remainder = abs(validated_left), abs(validated_right)
    old_x, current_x = 1, 0
    old_y, current_y = 0, 1

    while current_remainder != 0:
        quotient = old_remainder // current_remainder

        old_remainder, current_remainder = (
            current_remainder,
            old_remainder - quotient * current_remainder,
        )
        old_x, current_x = current_x, old_x - quotient * current_x
        old_y, current_y = current_y, old_y - quotient * current_y

    # The coefficients above apply to the absolute input values. Reverse a
    # coefficient's sign when its original input was negative.
    if validated_left < 0:
        old_x = -old_x
    if validated_right < 0:
        old_y = -old_y

    return old_remainder, old_x, old_y


def modular_inverse(value: int, modulus: int) -> int:
    """Return the unique inverse in ``0..modulus-1`` when it exists.

    The inverse exists only when ``gcd(value, modulus) == 1``. Use
    ``extended_gcd`` and raise ``ValueError`` when the values are not coprime.
    """

    validated_value = _require_integer(value, "Value")
    validated_modulus = _require_integer(modulus, "Modulus", minimum=2)

    gcd, value_coefficient, _ = extended_gcd(
        validated_value,
        validated_modulus,
    )

    if gcd != 1:
        raise ValueError(
            f"{validated_value} has no inverse modulo {validated_modulus}"
        )

    # Bézout gives value*x + modulus*y = 1. Reducing x modulo the
    # modulus produces the unique canonical inverse in 0..modulus-1.
    return value_coefficient % validated_modulus


def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """Compute ``base**exponent mod modulus`` with square-and-multiply.

    Do not calculate ``base**exponent`` first; RSA exponents are far too large.
    """

    validated_base = _require_integer(base, "Base")
    remaining_exponent = _require_integer(exponent, "Exponent", minimum=0)
    validated_modulus = _require_integer(modulus, "Modulus", minimum=1)

    result = 1 % validated_modulus
    current_base = validated_base % validated_modulus

    while remaining_exponent > 0:
        # A set low bit means this power of the base contributes to the
        # exponent's binary representation.
        if remaining_exponent & 1:
            result = (result * current_base) % validated_modulus

        current_base = (current_base * current_base) % validated_modulus
        remaining_exponent >>= 1

    return result


def is_probable_prime(
    candidate: int,
    rounds: int = DEFAULT_MILLER_RABIN_ROUNDS,
) -> bool:
    """Return whether ``candidate`` passes randomized Miller-Rabin testing.

    ``True`` means probably prime, not a mathematical proof of primality.
    """

    validated_candidate = _require_integer(candidate, "Candidate")
    validated_rounds = _require_integer(rounds, "Rounds", minimum=1)

    if validated_candidate < 2:
        return False

    if validated_candidate in SMALL_PRIMES:
        return True

    # This also rejects all remaining even candidates because 2 is included
    # in SMALL_PRIMES.
    for small_prime in SMALL_PRIMES:
        if validated_candidate % small_prime == 0:
            return False

    # Factor candidate - 1 into 2**s * d, where d is odd.
    d = validated_candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(validated_rounds):
        # randbelow(candidate - 3) returns 0..candidate-4, so adding 2
        # selects uniformly from the required interval 2..candidate-2.
        base = secrets.randbelow(validated_candidate - 3) + 2
        result = modular_exponentiation(base, d, validated_candidate)

        if result == 1 or result == validated_candidate - 1:
            continue

        # Look for -1 modulo candidate while repeatedly squaring. If it
        # appears, this base is not a witness to compositeness.
        for _ in range(s - 1):
            result = (result * result) % validated_candidate
            if result == validated_candidate - 1:
                break
        else:
            # This base proves that candidate is composite.
            return False

    return True


def generate_probable_prime(
    bits: int,
    public_exponent: int = DEFAULT_PUBLIC_EXPONENT,
    rounds: int = DEFAULT_MILLER_RABIN_ROUNDS,
) -> int:
    """Generate a random odd probable prime of exactly ``bits`` bits.

    The GCD condition ensures the public exponent will be invertible modulo
    both ``p - 1`` and ``q - 1`` during key generation.
    """

    validated_bits = _require_integer(bits, "Prime bit size", minimum=2)
    validated_exponent = _require_integer(
        public_exponent,
        "Public exponent",
        minimum=3,
    )
    validated_rounds = _require_integer(rounds, "Rounds", minimum=1)

    if validated_exponent % 2 == 0:
        raise ValueError("Public exponent must be odd")

    highest_bit = 1 << (validated_bits - 1)

    while True:
        candidate = secrets.randbits(validated_bits)

        # Force the top bit for the exact requested width and the low bit so
        # the candidate is odd.
        candidate |= highest_bit
        candidate |= 1

        if greatest_common_divisor(candidate - 1, validated_exponent) != 1:
            continue

        if is_probable_prime(candidate, validated_rounds):
            return candidate


def _validate_public_key(key: PublicKey) -> PublicKey:
    """Validate the simple ``(e, n)`` public-key representation.

    This checks the representation and basic RSA bounds. Without the secret
    factors of n, it cannot prove that e is coprime with the corresponding
    totient or that the key belongs to a particular private key.
    """

    if not isinstance(key, PublicKey):
        raise TypeError("Public key must be a PublicKey")

    exponent = _require_integer(key.exponent, "Public exponent", minimum=3)
    modulus = _require_integer(key.modulus, "Public modulus", minimum=3)

    if exponent % 2 == 0:
        raise ValueError("Public exponent must be odd")
    if exponent >= modulus:
        raise ValueError("Public exponent must be smaller than the modulus")

    return key


def _validate_private_key(key: PrivateKey) -> PrivateKey:
    """Validate the simple ``(d, n)`` private-key representation.

    This validates the stored integers and their basic bounds. It cannot
    establish that d is the inverse of some public exponent without the
    corresponding public key and secret prime factors.
    """

    if not isinstance(key, PrivateKey):
        raise TypeError("Private key must be a PrivateKey")

    exponent = _require_integer(key.exponent, "Private exponent", minimum=2)
    modulus = _require_integer(key.modulus, "Private modulus", minimum=3)

    if exponent >= modulus:
        raise ValueError("Private exponent must be smaller than the modulus")

    return key


def generate_keypair(
    bits: int,
    public_exponent: int = DEFAULT_PUBLIC_EXPONENT,
) -> KeyPair:
    """Generate a two-prime RSA key pair with an exact-size modulus.

    The standards express key validity using Carmichael's lambda(n). Computing
    d modulo phi(n) is the conventional course derivation and also satisfies
    that condition because lambda(n) divides phi(n) for two-prime RSA.
    """

    validated_bits = _require_integer(
        bits,
        "RSA modulus bit size",
        minimum=MINIMUM_EDUCATIONAL_KEY_BITS,
    )
    validated_exponent = _require_integer(
        public_exponent,
        "Public exponent",
        minimum=3,
    )

    if validated_bits % 2 != 0:
        raise ValueError("RSA modulus bit size must be even")
    if validated_exponent % 2 == 0:
        raise ValueError("Public exponent must be odd")

    prime_bits = validated_bits // 2

    while True:
        prime_p = generate_probable_prime(
            prime_bits,
            public_exponent=validated_exponent,
        )
        prime_q = generate_probable_prime(
            prime_bits,
            public_exponent=validated_exponent,
        )

        if prime_p == prime_q:
            continue

        modulus = prime_p * prime_q

        # Two half-width primes can produce a product that is one bit shorter
        # than requested. Retry so the reported key size is exact.
        if modulus.bit_length() != validated_bits:
            continue

        totient = (prime_p - 1) * (prime_q - 1)
        private_exponent = modular_inverse(validated_exponent, totient)

        public_key = _validate_public_key(
            PublicKey(exponent=validated_exponent, modulus=modulus)
        )
        private_key = _validate_private_key(
            PrivateKey(exponent=private_exponent, modulus=modulus)
        )

        return KeyPair(
            public=public_key,
            private=private_key,
            prime_p=prime_p,
            prime_q=prime_q,
        )


def encrypt_int(message: int, key: PublicKey) -> int:
    """Apply the textbook RSA encryption primitive to one integer.

    Require ``0 <= message < key.modulus`` and return ``message**e mod n``
    using ``modular_exponentiation``.
    """

    validated_key = _validate_public_key(key)
    validated_message = _require_integer(message, "Message", minimum=0)

    if validated_message >= validated_key.modulus:
        raise ValueError("Message must be smaller than the RSA modulus")

    return modular_exponentiation(
        validated_message,
        validated_key.exponent,
        validated_key.modulus,
    )


def decrypt_int(ciphertext: int, key: PrivateKey) -> int:
    """Apply the textbook RSA decryption primitive to one integer.

    Require ``0 <= ciphertext < key.modulus`` and return ``ciphertext**d mod n``
    using ``modular_exponentiation``.
    """

    validated_key = _validate_private_key(key)
    validated_ciphertext = _require_integer(
        ciphertext,
        "Ciphertext",
        minimum=0,
    )

    if validated_ciphertext >= validated_key.modulus:
        raise ValueError("Ciphertext must be smaller than the RSA modulus")

    return modular_exponentiation(
        validated_ciphertext,
        validated_key.exponent,
        validated_key.modulus,
    )


def maximum_text_payload_bytes(modulus: int) -> int:
    """Return a conservative payload size whose marked block is below ``modulus``.

    The encoded block is ``0x01 || payload``. Restricting its total length to
    ``floor((modulus.bit_length() - 1) / 8)`` bytes guarantees its integer is
    strictly less than the modulus. One byte is then reserved for the marker.
    """

    validated_modulus = _require_integer(modulus, "Modulus", minimum=3)

    encoded_block_bytes = (validated_modulus.bit_length() - 1) // 8
    payload_bytes = encoded_block_bytes - 1

    if payload_bytes < 1:
        raise ValueError(
            "RSA modulus is too small for a marker-prefixed text block"
        )

    return payload_bytes


def _encode_text_blocks(plaintext: str, modulus: int) -> tuple[int, ...]:
    """Encode UTF-8 into reversible, marker-prefixed integer blocks.

    TODO(student): encode the text, split it into ``maximum_text_payload_bytes``
    chunks, prefix every chunk with byte ``TEXT_BLOCK_MARKER``, and convert each
    marked byte string with ``int.from_bytes(..., 'big')``. Empty text produces
    an empty tuple.
    """

    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string")

    payload_size = maximum_text_payload_bytes(modulus)
    plaintext_bytes = plaintext.encode("utf-8")
    marker = bytes((TEXT_BLOCK_MARKER,))
    blocks: list[int] = []

    for offset in range(0, len(plaintext_bytes), payload_size):
        payload = plaintext_bytes[offset : offset + payload_size]
        marked_block = marker + payload
        block = int.from_bytes(marked_block, byteorder="big")

        # maximum_text_payload_bytes() should make this impossible. Keeping
        # the check here makes a future change to the encoding fail safely.
        if block >= modulus:
            raise ValueError("Encoded text block is not smaller than the modulus")

        blocks.append(block)

    return tuple(blocks)


def _decode_text_blocks(blocks: tuple[int, ...], modulus: int) -> str:
    """Reverse marker-prefixed integer blocks and decode strict UTF-8.

    TODO(student): validate each integer, restore its shortest big-endian byte
    representation, require and remove the leading marker, join the payloads,
    and decode UTF-8. Convert ``UnicodeDecodeError`` to a focused ``ValueError``.
    """

    if not isinstance(blocks, tuple):
        raise TypeError("Encoded text blocks must be a tuple")

    maximum_payload_size = maximum_text_payload_bytes(modulus)
    payload_parts: list[bytes] = []

    for index, block in enumerate(blocks):
        validated_block = _require_integer(
            block,
            f"Encoded block {index}",
            minimum=0,
        )

        if validated_block >= modulus:
            raise ValueError(f"Encoded block {index} must be smaller than the modulus")

        byte_length = max(1, (validated_block.bit_length() + 7) // 8)
        marked_block = validated_block.to_bytes(byte_length, byteorder="big")

        if marked_block[0] != TEXT_BLOCK_MARKER:
            raise ValueError(f"Encoded block {index} has an invalid marker")

        payload = marked_block[1:]
        if not payload:
            raise ValueError(f"Encoded block {index} has an empty payload")
        if len(payload) > maximum_payload_size:
            raise ValueError(f"Encoded block {index} exceeds the payload limit")

        payload_parts.append(payload)

    plaintext_bytes = b"".join(payload_parts)

    try:
        return plaintext_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("Decoded RSA blocks do not contain valid UTF-8") from error


def encrypt_text(plaintext: str, key: PublicKey) -> list[int]:
    """Encode UTF-8 blocks and encrypt each with textbook RSA.

    This operation is deterministic and not OAEP. It exists only to satisfy the
    assignment's plaintext-string and integer-ciphertext demonstration.
    """

    validated_key = _validate_public_key(key)
    plaintext_blocks = _encode_text_blocks(
        plaintext,
        validated_key.modulus,
    )

    ciphertext: list[int] = []
    for block in plaintext_blocks:
        ciphertext.append(encrypt_int(block, validated_key))

    return ciphertext


def decrypt_text(ciphertext: list[int], key: PrivateKey) -> str:
    """Decrypt textbook RSA integers and reconstruct the UTF-8 plaintext."""

    if not isinstance(ciphertext, list):
        raise TypeError("Ciphertext must be a list of integers")

    validated_key = _validate_private_key(key)
    plaintext_blocks: list[int] = []

    for block in ciphertext:
        plaintext_blocks.append(decrypt_int(block, validated_key))

    return _decode_text_blocks(
        tuple(plaintext_blocks),
        validated_key.modulus,
    )
