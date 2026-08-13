"""From-scratch implementation of single DES for the coursework project.

Fixed tables live in ``symmetric/des_tables.py`` so this file focuses on the
algorithmic logic and records detailed traces for terminal demonstrations.

Important terminology
---------------------
* A DES data block is exactly 64 bits (8 bytes).
* The supplied DES key is also 64 bits (8 bytes).
* Only 56 key bits are active; PC-1 discards the eight parity positions.
* DES has 16 Feistel rounds and each round subkey is 48 bits.
* Decryption uses the same round function with encryption subkeys reversed.

This implementation is educational. DES is obsolete, its 56-bit key space is
too small, ECB leaks repeated-block patterns, and from-scratch Python code is
not designed to resist timing or other side-channel attacks.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from common.padding import pkcs7_pad, pkcs7_unpad
from symmetric.des_tables import (
    EXPANSION_PERMUTATION,
    FINAL_PERMUTATION,
    INITIAL_PERMUTATION,
    PERMUTED_CHOICE_1,
    PERMUTED_CHOICE_2,
    P_PERMUTATION,
    ROUND_SHIFTS,
    S_BOXES,
    WEAK_AND_SEMI_WEAK_KEYS,
)


BLOCK_SIZE = 8
KEY_SIZE = 8
EFFECTIVE_KEY_BITS = 56
ROUND_COUNT = 16
MASK_28_BITS = (1 << 28) - 1
MASK_32_BITS = (1 << 32) - 1


@dataclass(frozen=True)
class DESKeyRound:
    """State of the key schedule after one round's left rotations."""

    round_number: int
    shift: int
    left_half: int       # C_i, 28 bits
    right_half: int      # D_i, 28 bits
    subkey: int          # K_i, 48 bits


@dataclass(frozen=True)
class DESRoundTrace:
    """Intermediate values from one Feistel round."""

    round_number: int
    left_input: int
    right_input: int
    subkey: int
    expanded_right: int
    mixed_with_key: int
    sbox_output: int
    p_output: int
    left_output: int
    right_output: int


@dataclass(frozen=True)
class DESTrace:
    """Complete information required for a DES coursework demonstration."""

    operation: str
    initial_permutation: int
    key_schedule: tuple[DESKeyRound, ...]  # Always K1 through K16.
    rounds: tuple[DESRoundTrace, ...]      # Records keys in actual use order.
    preoutput: int                         # R16 || L16.
    output: int

    @property
    def round_keys(self) -> tuple[int, ...]:
        """Expose K1..K16 directly for convenient terminal display."""

        return tuple(key_round.subkey for key_round in self.key_schedule)


def _require_exact_bytes(value: bytes, length: int, name: str) -> bytes:
    """Validate a bytes value used as a raw DES block or key."""

    if type(value) is not bytes:
        raise TypeError(f"{name} must be bytes, not {type(value).__name__}")
    if len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes, not {len(value)}")
    return value


def _permute(value: int, input_width: int, table: tuple[int, ...]) -> int:
    """Select bits using FIPS one-based, MSB-first positions.

    This single helper performs IP, IP^-1, E, P, PC-1, and PC-2. Repeated
    positions are allowed because the E table intentionally duplicates boundary
    bits; omitted positions are allowed because PC-1/PC-2 compress their input.

    Do not subtract one and then index a normal least-significant-bit-oriented
    integer: DES numbers bit 1 from the left, not from the right.
    """
    if type(value) is not int:
        raise TypeError(f"value must be an integer, not {type(value).__name__}")
    if type(input_width) is not int:
        raise TypeError(
            f"input_width must be an integer, not {type(input_width).__name__}"
        )
    if input_width < 1:
        raise ValueError("input_width must be positive")
    if type(table) is not tuple:
        raise TypeError(f"table must be a tuple, not {type(table).__name__}")
    if value < 0 or value >= (1 << input_width):
        raise ValueError(f"value must fit in {input_width} bits")
    for source_position in table:
        if type(source_position) is not int:
            raise TypeError("every table position must be an integer")
        if source_position < 1 or source_position > input_width:
            raise ValueError(f"table position {source_position} out of range")

    result = 0
    for source_position in table:
        result <<= 1
        bit = (value >> (input_width - source_position)) & 1
        result |= bit
    return result


def _rotate_left_28(value: int, amount: int) -> int:
    """Circularly rotate a 28-bit key half to the left.

    This is rotation, not ordinary shifting: bits leaving the left edge return
    at the right edge.
    """
    if type(value) is not int:
        raise TypeError(f"value must be an integer, not {type(value).__name__}")
    if type(amount) is not int:
        raise TypeError(f"amount must be an integer, not {type(amount).__name__}")
    if value < 0 or value >= (1 << 28):
        raise ValueError("value must fit in 28 bits")
    amount %= 28
    rotated = ((value << amount) | (value >> (28 - amount))) & MASK_28_BITS
    return rotated

def has_odd_parity(key: bytes) -> bool:
    """Return whether every key byte contains an odd number of one bits.

    Parity affects error detection, not the 56 active DES bits.
    """
    key = _require_exact_bytes(key, 8, "key")
    for byte in key:
        if byte.bit_count() % 2 == 0:
            return False
    return True

def set_odd_parity(key: bytes) -> bytes:
    """Set the least-significant bit of every byte to enforce odd parity.

    PC-1 omits these least-significant parity positions.
    """
    key = _require_exact_bytes(key, 8, "key")
    adjusted_key = bytearray(8)
    for i in range(8):
        byte = key[i] & 0xFE  # Clear the least significant bit
        if (byte.bit_count() % 2) == 0:  # If the count of 1s is even
            byte |= 0x01  # Set the least significant bit to make it odd
        adjusted_key[i] = byte
    return bytes(adjusted_key)

def is_weak_key(key: bytes) -> bool:
    """Return whether the parity-normalized key is weak or semi-weak."""
    key = _require_exact_bytes(key, 8, "key")
    normalized_key = set_odd_parity(key)
    return normalized_key in WEAK_AND_SEMI_WEAK_KEYS

def generate_key() -> bytes:
    """Generate an odd-parity, non-weak 8-byte DES key using ``secrets``."""
    while True:
        random_key = secrets.token_bytes(KEY_SIZE)
        key_with_parity = set_odd_parity(random_key)
        if not is_weak_key(key_with_parity):
            return key_with_parity

def build_key_schedule(key: bytes) -> tuple[DESKeyRound, ...]:
    """Return C_i, D_i, and K_i for all 16 encryption rounds.

    PC-2 selects 24 bits from C_i and 24 from D_i. Thinking of this as
    "discard four from each" is numerically fine, but it is a fixed selection
    and permutation—not truncation and not a generic compression algorithm.
    """
    key = _require_exact_bytes(key, 8, "key")
    key_integer = int.from_bytes(key, "big")
    permuted_key = _permute(key_integer, 64, PERMUTED_CHOICE_1)
    C = (permuted_key >> 28) & MASK_28_BITS
    D = permuted_key & MASK_28_BITS
    key_schedule = []
    for round_number, shift in enumerate(ROUND_SHIFTS, start=1):
        C = _rotate_left_28(C, shift)
        D = _rotate_left_28(D, shift)
        combined = (C << 28) | D
        subkey = _permute(combined, 56, PERMUTED_CHOICE_2)
        key_schedule.append(DESKeyRound(round_number, shift, C, D, subkey))
    return tuple(key_schedule)

def expand_key(key: bytes) -> tuple[int, ...]:
    """Return K1 through K16 as sixteen 48-bit integers."""

    key_schedule = build_key_schedule(key)
    return tuple(round.subkey for round in key_schedule)

def _sbox_substitute(value: int) -> int:
    """Apply S1..S8 to a 48-bit value and return 32 bits.

    A useful extraction for box index 0..7 is a right shift of
    ``42 - 6 * box_index``, followed by ``& 0b111111``.
    """
    if type(value) is not int:
        raise TypeError(f"value must be an integer, not {type(value).__name__}")
    if value < 0 or value >= (1 << 48):
        raise ValueError("value must fit in 48 bits")

    result = 0
    for box_index in range(8):
        # Extract the next six bits from most significant (S1) to least
        # significant (S8). For S1 the shift is 42; for S8 it is 0.
        chunk = (value >> (42 - 6 * box_index)) & 0b111111

        # If chunk is b1 b2 b3 b4 b5 b6, the S-box row is binary
        # b1b6. The first bit is therefore the TWO'S place, not merely ORed
        # into the final bit. This permits rows 0, 1, 2, and 3.
        first_bit = (chunk >> 5) & 1
        last_bit = chunk & 1
        row = (first_bit << 1) | last_bit

        # The four middle bits b2b3b4b5 form a column from 0 through 15.
        column = (chunk >> 1) & 0b1111

        # Append this box's four-bit output to the accumulated result.
        sbox_value = S_BOXES[box_index][row][column]
        result = (result << 4) | sbox_value

    return result


def _feistel(right: int, subkey: int) -> tuple[int, int, int, int]:
    """Return ``(expanded, mixed, sbox_output, p_output)`` for f(R, K).

    ``right`` is one 32-bit data half and ``subkey`` is the 48-bit key for
    the current DES round. Returning all four stages makes the operation easy
    to display and verify in the coursework trace.
    """
    if type(right) is not int:
        raise TypeError(f"right must be an integer, not {type(right).__name__}")
    if right < 0 or right >= (1 << 32):
        raise ValueError("right must fit in 32 bits")

    if type(subkey) is not int:
        raise TypeError(
            f"subkey must be an integer, not {type(subkey).__name__}"
        )
    if subkey < 0 or subkey >= (1 << 48):
        raise ValueError("subkey must fit in 48 bits")

    # E repeats selected boundary bits while expanding R from 32 to 48 bits.
    expanded = _permute(right, 32, EXPANSION_PERMUTATION)

    # Key mixing is bitwise XOR. Both operands are exactly 48 bits wide.
    mixed = expanded ^ subkey

    # The eight S-boxes convert eight 6-bit groups into eight 4-bit groups.
    sbox_output = _sbox_substitute(mixed)

    # P rearranges the 32 S-box output bits; it does not change their width.
    p_output = _permute(sbox_output, 32, P_PERMUTATION)

    return expanded, mixed, sbox_output, p_output


def _process_block(
    block: bytes,
    key: bytes,
    operation: str,
) -> tuple[bytes, DESTrace]:
    """Run the shared Feistel machinery for encryption or decryption.

    The recurrence always performs L_i = R_i-1. Avoid saying "the final round
    omits the swap" in code; explicitly forming R16 || L16 is unambiguous.
    """
    block = _require_exact_bytes(block, BLOCK_SIZE, "block")
    key = _require_exact_bytes(key, KEY_SIZE, "key")

    if type(operation) is not str:
        raise TypeError(
            f"operation must be a string, not {type(operation).__name__}"
        )
    if operation not in ("encrypt", "decrypt"):
        raise ValueError("operation must be 'encrypt' or 'decrypt'")

    # Always build and retain the encryption schedule K1 through K16. DES
    # decryption uses the same round function with those subkeys reversed.
    key_schedule = build_key_schedule(key)
    encryption_subkeys = tuple(key_round.subkey for key_round in key_schedule)
    if operation == "encrypt":
        selected_subkeys = encryption_subkeys
    else:
        selected_subkeys = tuple(reversed(encryption_subkeys))

    block_integer = int.from_bytes(block, "big")
    initial_permutation = _permute(
        block_integer,
        64,
        INITIAL_PERMUTATION,
    )

    # IP output is L0 || R0: the upper and lower 32-bit halves respectively.
    left = (initial_permutation >> 32) & MASK_32_BITS
    right = initial_permutation & MASK_32_BITS
    round_traces: list[DESRoundTrace] = []

    for round_number, subkey in enumerate(selected_subkeys, start=1):
        left_input = left
        right_input = right

        expanded, mixed, sbox_output, p_output = _feistel(
            right_input,
            subkey,
        )

        # Feistel recurrence:
        # L_i = R_(i-1)
        # R_i = L_(i-1) XOR f(R_(i-1), K_i)
        new_left = right_input & MASK_32_BITS
        new_right = (left_input ^ p_output) & MASK_32_BITS

        round_traces.append(
            DESRoundTrace(
                round_number=round_number,
                left_input=left_input,
                right_input=right_input,
                subkey=subkey,
                expanded_right=expanded,
                mixed_with_key=mixed,
                sbox_output=sbox_output,
                p_output=p_output,
                left_output=new_left,
                right_output=new_right,
            )
        )

        left, right = new_left, new_right

    # DES places the final halves in reversed order before IP^-1.
    preoutput = (right << 32) | left  # R16 || L16
    output_integer = _permute(preoutput, 64, FINAL_PERMUTATION)
    output_bytes = output_integer.to_bytes(BLOCK_SIZE, "big")

    trace = DESTrace(
        operation=operation,
        initial_permutation=initial_permutation,
        key_schedule=key_schedule,
        rounds=tuple(round_traces),
        preoutput=preoutput,
        output=output_integer,
    )

    return output_bytes, trace


def encrypt_block(block: bytes, key: bytes) -> tuple[bytes, DESTrace]:
    """Encrypt exactly one 8-byte block and return its full trace.

    Validation, key scheduling, the 16 rounds, and trace construction are all
    handled by ``_process_block`` so encryption and decryption cannot drift
    into separate implementations.
    """
    return _process_block(block, key, operation="encrypt")


def decrypt_block(block: bytes, key: bytes) -> tuple[bytes, DESTrace]:
    """Decrypt exactly one block using K16 through K1.

    DES decryption runs the same Feistel machinery as encryption; only the
    order in which the round subkeys are used changes.
    """
    return _process_block(block, key, operation="decrypt")


def encrypt_ecb(plaintext: bytes, key: bytes) -> tuple[bytes, tuple[DESTrace, ...]]:
    """PKCS#7-pad and independently encrypt every block for the coursework UI.

    ECB is chosen only to expose independent DES blocks during demonstration.
    It leaks patterns and must be labelled insecure in the UI/report.
    """
    if type(plaintext) is not bytes:
        raise TypeError(
            f"plaintext must be bytes, not {type(plaintext).__name__}"
        )
    key = _require_exact_bytes(key, KEY_SIZE, "key")

    # Padding guarantees at least one block and makes the total byte length a
    # multiple of DES's eight-byte block size.
    padded_plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext_blocks: list[bytes] = []
    traces: list[DESTrace] = []

    for offset in range(0, len(padded_plaintext), BLOCK_SIZE):
        plaintext_block = padded_plaintext[offset : offset + BLOCK_SIZE]
        ciphertext_block, trace = encrypt_block(plaintext_block, key)
        ciphertext_blocks.append(ciphertext_block)
        traces.append(trace)

    return b"".join(ciphertext_blocks), tuple(traces)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> tuple[bytes, tuple[DESTrace, ...]]:
    """Decrypt aligned ECB blocks and strictly remove PKCS#7 padding.

    Padding is removed after joining all decrypted blocks because PKCS#7
    padding belongs only to the end of the complete message, not every block.
    """
    if type(ciphertext) is not bytes:
        raise TypeError(
            f"ciphertext must be bytes, not {type(ciphertext).__name__}"
        )
    key = _require_exact_bytes(key, KEY_SIZE, "key")

    if len(ciphertext) == 0:
        raise ValueError("ciphertext must contain at least one DES block")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"ciphertext length must be a multiple of {BLOCK_SIZE} bytes"
        )

    padded_plaintext_blocks: list[bytes] = []
    traces: list[DESTrace] = []

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        ciphertext_block = ciphertext[offset : offset + BLOCK_SIZE]
        plaintext_block, trace = decrypt_block(ciphertext_block, key)
        padded_plaintext_blocks.append(plaintext_block)
        traces.append(trace)

    padded_plaintext = b"".join(padded_plaintext_blocks)
    plaintext = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    return plaintext, tuple(traces)
