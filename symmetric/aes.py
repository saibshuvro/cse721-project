"""Guided, from-scratch AES-128 implementation template.

This project deliberately implements AES-128 only:

* block size: 16 bytes (128 bits);
* key size: 16 bytes (128 bits);
* rounds: 10;
* round keys: 11, including K0 for the initial AddRoundKey.

The fixed lookup tables and matrices live in ``symmetric/aes_tables.py``.
Complete the TODO functions in the order documented in ``docs/aes-guide.md``.
Core functions must not call ``input`` or ``print``.

State convention
----------------
AES fills its 4 x 4 state by columns, not by rows:

    state[row][column] = block[row + 4 * column]

Therefore bytes ``00 11 22 33 44 ... ff`` become:

    00 44 88 cc
    11 55 99 dd
    22 66 aa ee
    33 77 bb ff

Keeping this convention consistent is the most important implementation rule.

This is educational code. A from-scratch Python implementation is not
constant-time, and the optional ECB wrapper leaks repeated-block patterns.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import cast

from common.padding import pkcs7_pad, pkcs7_unpad
from symmetric.aes_tables import (
    INV_MIX_COLUMNS_MATRIX,
    INV_S_BOX,
    MIX_COLUMNS_MATRIX,
    ROUND_CONSTANTS,
    S_BOX,
)


BLOCK_SIZE = 16
KEY_SIZE = 16
ROUND_COUNT = 10
STATE_SIZE = 4
WORD_SIZE = 4
EXPANDED_WORD_COUNT = 44

Word = tuple[int, int, int, int]
State = tuple[tuple[int, ...], ...]
Matrix = tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class AESStageTrace:
    """One named AES transformation and its resulting state.

    ``state`` is serialized in normal AES block byte order so it can be shown
    directly as 32 hexadecimal digits. ``round_key`` is populated for an
    AddRoundKey stage and is otherwise ``None``.
    """

    round_number: int
    transformation: str
    state: bytes
    round_key: bytes | None = None


@dataclass(frozen=True)
class AESTrace:
    """Round keys and transformation snapshots for one AES-128 block."""

    operation: str
    round_keys: tuple[bytes, ...]  # Always K0 through K10.
    stages: tuple[AESStageTrace, ...]
    output: bytes


def _require_exact_bytes(value: bytes, length: int, name: str) -> bytes:
    """Validate a raw AES block, key, or round key.

    The exact-type check deliberately rejects mutable ``bytearray`` values.
    Keeping blocks and keys immutable prevents callers from changing them while
    an AES operation is in progress.
    """

    # ``isinstance(value, bytes)`` would also accept subclasses of ``bytes``.
    # This project uses exact raw byte strings at its cryptographic boundary,
    # so require the concrete built-in type instead.
    if type(value) is not bytes:
        raise TypeError(f"{name} must be bytes, not {type(value).__name__}")

    # AES-128 blocks, keys, and expanded round keys are each exactly 16 bytes.
    # The generic ``length`` argument lets this helper express that constraint
    # wherever it is called without duplicating validation logic.
    if len(value) != length:
        raise ValueError(
            f"{name} must be exactly {length} bytes, not {len(value)}"
        )

    return value


def _validate_state(state: State) -> State:
    """Require a 4 x 4 immutable state containing byte values 0..255.

    Returning the state makes this helper convenient inside transformations:
    callers can write ``state = _validate_state(state)`` before using it.
    """

    # A State is intentionally immutable. Requiring the exact tuple type also
    # keeps all AES helpers consistent instead of accepting a mixture of lists,
    # tuple subclasses, and tuples.
    if type(state) is not tuple:
        raise TypeError(
            f"AES state must be a tuple of rows, not {type(state).__name__}"
        )
    if len(state) != STATE_SIZE:
        raise ValueError(
            f"AES state must contain exactly {STATE_SIZE} rows, not {len(state)}"
        )

    for row_index, row in enumerate(state):
        if type(row) is not tuple:
            raise TypeError(
                f"AES state row {row_index} must be a tuple, "
                f"not {type(row).__name__}"
            )
        if len(row) != STATE_SIZE:
            raise ValueError(
                f"AES state row {row_index} must contain exactly "
                f"{STATE_SIZE} bytes, not {len(row)}"
            )

        for column_index, value in enumerate(row):
            # Use an exact-type check because ``bool`` is a subclass of ``int``
            # in Python, but True and False are not suitable state-byte inputs.
            if type(value) is not int:
                raise TypeError(
                    f"AES state byte at row {row_index}, column {column_index} "
                    f"must be an integer, not {type(value).__name__}"
                )
            if not 0 <= value <= 0xFF:
                raise ValueError(
                    f"AES state byte at row {row_index}, column {column_index} "
                    f"must be between 0 and 255, not {value}"
                )

    return state


def _bytes_to_state(block: bytes) -> State:
    """Convert 16 bytes into the FIPS column-major AES state.

    Do not split the input into four consecutive rows. Consecutive groups of
    four input bytes form the COLUMNS of the AES state.
    """

    block = _require_exact_bytes(block, BLOCK_SIZE, "AES block")

    # For each row, collect one byte from each of the four input columns.
    # Example: row 0 receives input positions 0, 4, 8, and 12.
    state_rows: list[tuple[int, ...]] = []
    for row_index in range(STATE_SIZE):
        row_values: list[int] = []

        for column_index in range(STATE_SIZE):
            block_index = row_index + STATE_SIZE * column_index
            row_values.append(block[block_index])

        state_rows.append(tuple(row_values))

    return tuple(state_rows)


def _state_to_bytes(state: State) -> bytes:
    """Serialize an AES state by columns, reversing ``_bytes_to_state``.

    Columns are visited before rows so the first output bytes are state
    positions ``[0][0]``, ``[1][0]``, ``[2][0]``, and ``[3][0]``.
    """

    state = _validate_state(state)

    block_values: list[int] = []

    # Visit one complete column at a time to reverse _bytes_to_state.
    for column_index in range(STATE_SIZE):
        for row_index in range(STATE_SIZE):
            block_values.append(state[row_index][column_index])

    return bytes(block_values)


def generate_key() -> bytes:
    """Generate an unpredictable 16-byte AES-128 key with ``secrets``.

    AES has no DES-style parity bits or standard weak-key rejection step. Every
    16-byte value is a valid AES-128 key for this API.
    """

    # ``secrets.token_bytes`` obtains randomness from the operating system and
    # is suitable for cryptographic keys. Do not use ``random`` for this task.
    return secrets.token_bytes(KEY_SIZE)


def _validate_word(word: object, name: str = "AES word") -> Word:
    """Validate an unknown value and narrow it to a four-byte AES word.

    Accepting ``object`` is intentional: before validation, callers may have a
    variable-length tuple (such as a row from ``Matrix``) or an invalid type.
    """

    if type(word) is not tuple:
        raise TypeError(f"{name} must be a tuple, not {type(word).__name__}")
    if len(word) != WORD_SIZE:
        raise ValueError(
            f"{name} must contain exactly {WORD_SIZE} bytes, not {len(word)}"
        )

    for index, value in enumerate(word):
        # An exact type check prevents True and False from being accepted as
        # the integers 1 and 0.
        if type(value) is not int:
            raise TypeError(
                f"{name} byte {index} must be an integer, "
                f"not {type(value).__name__}"
            )
        if not 0 <= value <= 0xFF:
            raise ValueError(
                f"{name} byte {index} must be between 0 and 255, not {value}"
            )

    # The checks above prove the tuple has exactly four integer byte values.
    # Static type checkers cannot infer a fixed tuple length from ``len``, so
    # narrow it explicitly only after those runtime checks have succeeded.
    return cast(Word, word)


def _xor_words(left: Word, right: Word) -> Word:
    """XOR corresponding bytes of two AES key-schedule words.

    XOR operates independently at each position; it does not carry between
    bytes as integer addition would.
    """

    left = _validate_word(left, "left AES word")
    right = _validate_word(right, "right AES word")

    return (
        left[0] ^ right[0],
        left[1] ^ right[1],
        left[2] ^ right[2],
        left[3] ^ right[3],
    )


def _rot_word(word: Word) -> Word:
    """Rotate ``(a0, a1, a2, a3)`` into ``(a1, a2, a3, a0)``."""

    word = _validate_word(word)

    # This is a cyclic rotation: the first byte wraps around to the end and no
    # byte is discarded. RotWord is used once per generated AES-128 round key.
    return (word[1], word[2], word[3], word[0])


def _sub_word(word: Word) -> Word:
    """Apply the AES S-box independently to all four bytes of a word."""

    word = _validate_word(word)

    # Each word value is already a valid byte, so it can be used directly as
    # an index into the fixed 256-entry S-box from FIPS 197.
    return (
        S_BOX[word[0]],
        S_BOX[word[1]],
        S_BOX[word[2]],
        S_BOX[word[3]],
    )


def expand_key(key: bytes) -> tuple[bytes, ...]:
    """Expand one AES-128 key into K0 through K10.

    AES-128 needs 44 words because AddRoundKey is performed 11 times. Rcon is
    applied only to the first generated word of each new round key.
    """

    key = _require_exact_bytes(key, KEY_SIZE, "AES-128 key")

    # The original 16-byte key is the first four words, w[0] through w[3].
    # Words use consecutive key bytes; unlike the AES state, no matrix layout
    # conversion is needed here.
    words: list[Word] = []
    for offset in range(0, KEY_SIZE, WORD_SIZE):
        word: Word = (
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        )
        words.append(word)

    # Generate w[4] through w[43]. Each new word depends on the word directly
    # before it and the word four positions earlier.
    for word_index in range(WORD_SIZE, EXPANDED_WORD_COUNT):
        temporary_word = words[word_index - 1]

        if word_index % WORD_SIZE == 0:
            # At the start of each round key, apply the key-schedule core:
            # RotWord, SubWord, then Rcon in the first byte only.
            temporary_word = _sub_word(_rot_word(temporary_word))
            round_constant = ROUND_CONSTANTS[word_index // WORD_SIZE - 1]
            temporary_word = (
                temporary_word[0] ^ round_constant,
                temporary_word[1],
                temporary_word[2],
                temporary_word[3],
            )

        words.append(_xor_words(words[word_index - WORD_SIZE], temporary_word))

    # Four consecutive words make one 16-byte round key. This yields K0 (the
    # original key) followed by K1 through K10 in encryption order.
    round_keys: list[bytes] = []
    for first_word in range(0, EXPANDED_WORD_COUNT, WORD_SIZE):
        round_key_words = words[first_word : first_word + WORD_SIZE]
        round_key_values: list[int] = []

        for word in round_key_words:
            for byte in word:
                round_key_values.append(byte)

        round_keys.append(bytes(round_key_values))

    return tuple(round_keys)


def _sub_bytes(state: State) -> State:
    """Apply ``S_BOX`` independently to every state byte."""

    state = _validate_state(state)

    # SubBytes changes each byte's value but leaves it in the same row and
    # column. Every input byte is a direct index into the 256-entry AES S-box.
    substituted_rows: list[tuple[int, ...]] = []
    for row in state:
        substituted_values: list[int] = []

        for value in row:
            substituted_values.append(S_BOX[value])

        substituted_rows.append(tuple(substituted_values))

    return tuple(substituted_rows)


def _inv_sub_bytes(state: State) -> State:
    """Apply ``INV_S_BOX`` independently to every state byte."""

    state = _validate_state(state)

    # INV_S_BOX was constructed so that INV_S_BOX[S_BOX[value]] == value for
    # every possible byte. It therefore reverses SubBytes one byte at a time.
    restored_rows: list[tuple[int, ...]] = []
    for row in state:
        restored_values: list[int] = []

        for value in row:
            restored_values.append(INV_S_BOX[value])

        restored_rows.append(tuple(restored_values))

    return tuple(restored_rows)


def _shift_rows(state: State) -> State:
    """Cyclically shift state row r left by r byte positions.

    Row 0 is unchanged; rows 1, 2, and 3 shift left by 1, 2, and 3.
    This moves bytes between columns but never between rows.
    """

    state = _validate_state(state)

    shifted_rows: list[tuple[int, ...]] = []
    for row_index, row in enumerate(state):
        # Slicing performs the cyclic left rotation. For example, row 2 changes
        # from (a, b, c, d) to (c, d, a, b).
        shifted_row = row[row_index:] + row[:row_index]
        shifted_rows.append(shifted_row)

    return tuple(shifted_rows)


def _inv_shift_rows(state: State) -> State:
    """Cyclically shift state row r right by r byte positions."""

    state = _validate_state(state)

    restored_rows: list[tuple[int, ...]] = []
    for row_index, row in enumerate(state):
        if row_index == 0:
            restored_row = row
        else:
            # Move the last row_index values to the front: a cyclic right shift.
            restored_row = row[-row_index:] + row[:-row_index]

        restored_rows.append(restored_row)

    return tuple(restored_rows)


def _validate_byte(value: int, name: str = "AES byte") -> int:
    """Require one integer in the byte range 0 through 255."""

    # ``bool`` is an ``int`` subclass in Python, so use an exact type check.
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer, not {type(value).__name__}")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be between 0 and 255, not {value}")
    return value


def _xtime(value: int) -> int:
    """Multiply one byte by {02} in AES's finite field GF(2^8).

    The ``0x1B`` reduction comes from the AES irreducible polynomial
    x^8 + x^4 + x^3 + x + 1. This is not ordinary integer multiplication.
    """

    value = _validate_byte(value)

    # Multiplication by x is a one-bit left shift. Keep only eight bits because
    # an element of GF(2^8) must remain one byte.
    product = (value << 1) & 0xFF

    # If the discarded high bit was set, the shifted polynomial had degree 8.
    # Reduce it modulo AES's irreducible polynomial using XOR with 0x1B.
    if value & 0x80:
        product ^= 0x1B

    return product


def _gf_multiply(left: int, right: int) -> int:
    """Multiply two bytes in GF(2^8) without a crypto/math library.

    This one helper supports coefficients 01/02/03 for MixColumns and
    09/0B/0D/0E for InvMixColumns.
    """

    multiplicand = _validate_byte(left, "left field element")
    multiplier = _validate_byte(right, "right field element")
    product = 0

    # Each of the multiplier's eight bits selects one successive field-doubled
    # version of the multiplicand. Field addition is XOR, not integer addition.
    for _ in range(8):
        if multiplier & 0x01:
            product ^= multiplicand

        multiplicand = _xtime(multiplicand)
        multiplier >>= 1

    return product


def _validate_matrix(matrix: Matrix, name: str = "AES matrix") -> Matrix:
    """Require a 4 x 4 immutable matrix of byte coefficients."""

    if type(matrix) is not tuple:
        raise TypeError(f"{name} must be a tuple, not {type(matrix).__name__}")
    if len(matrix) != STATE_SIZE:
        raise ValueError(
            f"{name} must contain exactly {STATE_SIZE} rows, not {len(matrix)}"
        )

    # A matrix row has the same four-byte structure as an AES word, so reuse
    # that validator instead of duplicating its type and range checks.
    for row_index, row in enumerate(matrix):
        _validate_word(row, f"{name} row {row_index}")

    return matrix


def _mix_single_column(column: Word, matrix: Matrix) -> Word:
    """Multiply one four-byte column by a fixed 4 x 4 AES matrix.

    Never reuse a partly overwritten output as an input.
    """

    column = _validate_word(column, "AES state column")
    matrix = _validate_matrix(matrix)
    mixed_values: list[int] = []

    # This is matrix-vector multiplication, except multiplication takes place
    # in GF(2^8) and addition in that field is XOR.
    for output_row in range(STATE_SIZE):
        mixed_byte = 0
        for input_row in range(STATE_SIZE):
            mixed_byte ^= _gf_multiply(
                matrix[output_row][input_row],
                column[input_row],
            )
        mixed_values.append(mixed_byte)

    return (
        mixed_values[0],
        mixed_values[1],
        mixed_values[2],
        mixed_values[3],
    )


def _columns_to_state(columns: list[Word]) -> State:
    """Rebuild the row-oriented AES state from four vertical columns."""

    if len(columns) != STATE_SIZE:
        raise ValueError(
            f"AES state must contain exactly {STATE_SIZE} columns, "
            f"not {len(columns)}"
        )

    for column_index, column in enumerate(columns):
        _validate_word(column, f"AES state column {column_index}")

    state_rows: list[tuple[int, ...]] = []
    for row_index in range(STATE_SIZE):
        row_values: list[int] = []

        for column_index in range(STATE_SIZE):
            row_values.append(columns[column_index][row_index])

        state_rows.append(tuple(row_values))

    return tuple(state_rows)


def _mix_columns(state: State) -> State:
    """Mix each state column with ``MIX_COLUMNS_MATRIX`` independently."""

    state = _validate_state(state)
    mixed_columns: list[Word] = []

    # Extract each vertical state column before transforming it. Keeping the
    # original state immutable ensures no column reads partly updated values.
    for column_index in range(STATE_SIZE):
        column: Word = (
            state[0][column_index],
            state[1][column_index],
            state[2][column_index],
            state[3][column_index],
        )
        mixed_columns.append(_mix_single_column(column, MIX_COLUMNS_MATRIX))

    return _columns_to_state(mixed_columns)


def _inv_mix_columns(state: State) -> State:
    """Mix each state column with ``INV_MIX_COLUMNS_MATRIX`` independently."""

    state = _validate_state(state)
    restored_columns: list[Word] = []

    # The structure is the same as MixColumns; only the standardized matrix
    # coefficients differ. Those coefficients reverse the forward mixing in
    # GF(2^8), restoring each original column.
    for column_index in range(STATE_SIZE):
        column: Word = (
            state[0][column_index],
            state[1][column_index],
            state[2][column_index],
            state[3][column_index],
        )
        restored_columns.append(
            _mix_single_column(column, INV_MIX_COLUMNS_MATRIX)
        )

    return _columns_to_state(restored_columns)


def _add_round_key(state: State, round_key: bytes) -> State:
    """XOR one 16-byte round key into the state.

    The round key uses the same column-major relation as ``_bytes_to_state``.
    AddRoundKey is its own inverse because XORing the same value twice cancels
    it: ``(state XOR key) XOR key == state``.
    """

    state = _validate_state(state)
    round_key = _require_exact_bytes(round_key, BLOCK_SIZE, "AES round key")
    key_state = _bytes_to_state(round_key)

    # XOR corresponding row/column positions. This produces a new immutable
    # state and does not modify either input.
    result_rows: list[tuple[int, ...]] = []
    for row_index in range(STATE_SIZE):
        result_values: list[int] = []

        for column_index in range(STATE_SIZE):
            state_byte = state[row_index][column_index]
            key_byte = key_state[row_index][column_index]
            result_values.append(state_byte ^ key_byte)

        result_rows.append(tuple(result_values))

    return tuple(result_rows)


def encrypt_block(block: bytes, key: bytes) -> tuple[bytes, AESTrace]:
    """Encrypt exactly one 16-byte block and return all trace stages.

    AES is a substitution-permutation network, not a Feistel cipher: the whole
    state is transformed each round and encryption/decryption are distinct
    sequences of forward/inverse operations.
    """

    block = _require_exact_bytes(block, BLOCK_SIZE, "AES plaintext block")
    key = _require_exact_bytes(key, KEY_SIZE, "AES-128 key")
    round_keys = expand_key(key)
    state = _bytes_to_state(block)
    stages: list[AESStageTrace] = []

    # AES begins with key addition before the first full transformation round.
    # This uses K0, which is the original 16-byte AES key.
    state = _add_round_key(state, round_keys[0])
    stages.append(
        AESStageTrace(
            round_number=0,
            transformation="AddRoundKey",
            state=_state_to_bytes(state),
            round_key=round_keys[0],
        )
    )

    # Rounds 1 through 9 contain all four forward AES transformations.
    for round_number in range(1, ROUND_COUNT):
        state = _sub_bytes(state)
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="SubBytes",
                state=_state_to_bytes(state),
            )
        )

        state = _shift_rows(state)
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="ShiftRows",
                state=_state_to_bytes(state),
            )
        )

        state = _mix_columns(state)
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="MixColumns",
                state=_state_to_bytes(state),
            )
        )

        state = _add_round_key(state, round_keys[round_number])
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="AddRoundKey",
                state=_state_to_bytes(state),
                round_key=round_keys[round_number],
            )
        )

    # The tenth and final round deliberately omits MixColumns.
    state = _sub_bytes(state)
    stages.append(
        AESStageTrace(
            round_number=ROUND_COUNT,
            transformation="SubBytes",
            state=_state_to_bytes(state),
        )
    )

    state = _shift_rows(state)
    stages.append(
        AESStageTrace(
            round_number=ROUND_COUNT,
            transformation="ShiftRows",
            state=_state_to_bytes(state),
        )
    )

    state = _add_round_key(state, round_keys[ROUND_COUNT])
    output = _state_to_bytes(state)
    stages.append(
        AESStageTrace(
            round_number=ROUND_COUNT,
            transformation="AddRoundKey",
            state=output,
            round_key=round_keys[ROUND_COUNT],
        )
    )

    trace = AESTrace(
        operation="encrypt",
        round_keys=round_keys,
        stages=tuple(stages),
        output=output,
    )
    return output, trace


def decrypt_block(block: bytes, key: bytes) -> tuple[bytes, AESTrace]:
    """Decrypt exactly one AES-128 block using the standard inverse cipher.

    Do not simply run the encryption loop backward, and do not apply
    InvMixColumns in the final inverse round.
    """

    block = _require_exact_bytes(block, BLOCK_SIZE, "AES ciphertext block")
    key = _require_exact_bytes(key, KEY_SIZE, "AES-128 key")
    round_keys = expand_key(key)
    state = _bytes_to_state(block)
    stages: list[AESStageTrace] = []

    # Decryption starts with the last encryption round key, K10.
    state = _add_round_key(state, round_keys[ROUND_COUNT])
    stages.append(
        AESStageTrace(
            round_number=ROUND_COUNT,
            transformation="AddRoundKey",
            state=_state_to_bytes(state),
            round_key=round_keys[ROUND_COUNT],
        )
    )

    # Inverse rounds 9 down to 1 use the inverse transformations in their
    # standard order and consume the corresponding round key after InvSubBytes.
    for round_number in range(ROUND_COUNT - 1, 0, -1):
        state = _inv_shift_rows(state)
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="InvShiftRows",
                state=_state_to_bytes(state),
            )
        )

        state = _inv_sub_bytes(state)
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="InvSubBytes",
                state=_state_to_bytes(state),
            )
        )

        state = _add_round_key(state, round_keys[round_number])
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="AddRoundKey",
                state=_state_to_bytes(state),
                round_key=round_keys[round_number],
            )
        )

        state = _inv_mix_columns(state)
        stages.append(
            AESStageTrace(
                round_number=round_number,
                transformation="InvMixColumns",
                state=_state_to_bytes(state),
            )
        )

    # The final inverse round corresponds to encryption's initial key addition.
    # Like encryption's round 10, it deliberately has no column-mixing stage.
    state = _inv_shift_rows(state)
    stages.append(
        AESStageTrace(
            round_number=0,
            transformation="InvShiftRows",
            state=_state_to_bytes(state),
        )
    )

    state = _inv_sub_bytes(state)
    stages.append(
        AESStageTrace(
            round_number=0,
            transformation="InvSubBytes",
            state=_state_to_bytes(state),
        )
    )

    state = _add_round_key(state, round_keys[0])
    output = _state_to_bytes(state)
    stages.append(
        AESStageTrace(
            round_number=0,
            transformation="AddRoundKey",
            state=output,
            round_key=round_keys[0],
        )
    )

    trace = AESTrace(
        operation="decrypt",
        round_keys=round_keys,
        stages=tuple(stages),
        output=output,
    )
    return output, trace


def encrypt_ecb(plaintext: bytes, key: bytes) -> tuple[bytes, tuple[AESTrace, ...]]:
    """PKCS#7-pad and independently encrypt all 16-byte blocks.

    ECB is included only for a transparent coursework demonstration. It leaks
    repeated-block patterns and must not be presented as secure application
    encryption.
    """

    if type(plaintext) is not bytes:
        raise TypeError(
            f"plaintext must be bytes, not {type(plaintext).__name__}"
        )
    key = _require_exact_bytes(key, KEY_SIZE, "AES-128 key")

    # PKCS#7 always adds padding. Empty input becomes one complete padding
    # block, and already aligned input receives an additional full block.
    padded_plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext_blocks: list[bytes] = []
    traces: list[AESTrace] = []

    for offset in range(0, len(padded_plaintext), BLOCK_SIZE):
        plaintext_block = padded_plaintext[offset : offset + BLOCK_SIZE]
        ciphertext_block, trace = encrypt_block(plaintext_block, key)
        ciphertext_blocks.append(ciphertext_block)
        traces.append(trace)

    return b"".join(ciphertext_blocks), tuple(traces)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> tuple[bytes, tuple[AESTrace, ...]]:
    """Decrypt aligned blocks and strictly remove PKCS#7 padding.

    Padding is removed only after all decrypted blocks have been joined because
    it belongs to the end of the complete message, not to each individual
    block.
    """

    if type(ciphertext) is not bytes:
        raise TypeError(
            f"ciphertext must be bytes, not {type(ciphertext).__name__}"
        )
    key = _require_exact_bytes(key, KEY_SIZE, "AES-128 key")

    # Valid output from encrypt_ecb always contains at least one complete block
    # because PKCS#7 pads even an empty plaintext.
    if len(ciphertext) == 0:
        raise ValueError("ciphertext must contain at least one AES block")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            f"ciphertext length must be a multiple of {BLOCK_SIZE} bytes"
        )

    padded_plaintext_blocks: list[bytes] = []
    traces: list[AESTrace] = []

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        ciphertext_block = ciphertext[offset : offset + BLOCK_SIZE]
        plaintext_block, trace = decrypt_block(ciphertext_block, key)
        padded_plaintext_blocks.append(plaintext_block)
        traces.append(trace)

    padded_plaintext = b"".join(padded_plaintext_blocks)
    plaintext = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    return plaintext, tuple(traces)
