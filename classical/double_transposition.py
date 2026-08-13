"""Guided template for a row-then-column double transposition cipher.

This file is intentionally NOT a completed solution. Fill in the sections
marked ``TODO(student)`` in the order given in
``docs/double-transposition-guide.md``.

Documented project assumption
-----------------------------
The assignment names a "first permutation key" and "second permutation key"
without defining their direction. This project interprets them as:

* first key: row permutation;
* second key: column permutation.

The internal representation is zero-based. For example, the row key
``(2, 0, 1)`` means that the output grid takes old row 2 first, old row 0
second, and old row 1 third. The CLI will accept the friendlier one-based text
``"3 1 2"`` and convert it with ``parse_permutation_key``.

Messages may occupy more than one grid. Each grid has
``len(row_key) * len(column_key)`` characters. Only the final grid is padded,
and the exact padding length is recorded so decryption never has to guess.
"""

from __future__ import annotations

from dataclasses import dataclass

from classical.frequency_analysis import letter_counts


Grid = tuple[tuple[str, ...], ...]
PADDING_CHARACTER = "~"


@dataclass(frozen=True)
class BlockTrace:
    """The three grids produced while processing one block.

    During encryption:
        input_grid -> after_first_step (rows) -> after_second_step (columns)

    During decryption:
        ciphertext grid -> after_first_step (inverse columns)
                        -> after_second_step (inverse rows/plaintext grid)
    """

    input_grid: Grid
    after_first_step: Grid
    after_second_step: Grid


@dataclass(frozen=True)
class TranspositionTrace:
    """All intermediate blocks needed for terminal display and explanation."""

    operation: str
    blocks: tuple[BlockTrace, ...]
    padding_length: int


def validate_permutation(key: tuple[int, ...], name: str = "Permutation key") -> tuple[int, ...]:
    """Validate and return a zero-based permutation.

    A valid length-three key contains exactly ``0, 1, 2`` in any order.
    """
    if type(key) is not tuple:
        raise TypeError(f"{name} must be a tuple, not {type(key).__name__}")
    if len(key) == 0:
        raise ValueError(f"{name} must not be empty")
    for i, value in enumerate(key):
        if type(value) is not int:
            raise TypeError(f"{name} item {i} must be an integer, not {type(value).__name__}")
    if len(set(key)) != len(key):
        raise ValueError(f"{name} must not contain duplicate values")
    if set(key) != set(range(len(key))):
        raise ValueError(f"{name} must contain exactly the integers 0..{len(key)-1}")
    return key

    # raise NotImplementedError("TODO(student): validate a zero-based permutation")


def parse_permutation_key(text: str, name: str = "Permutation key") -> tuple[int, ...]:
    """Convert one-based terminal input such as ``"3 1 2"`` to ``(2, 0, 1)``.

    Do not silently sort the key: its supplied order is the permutation.
    """
    if type(text) is not str:
        raise TypeError(f"{name} must be a string, not {type(text).__name__}")

    tokens = text.split()
    if len(tokens) == 0:
        raise ValueError(f"{name} must not be empty")

    one_based_values: list[int] = []
    for token in tokens:
        try:
            one_based_values.append(int(token))
        except ValueError as error:
            raise ValueError(f"{name} contains a non-integer token: {token!r}") from error

    # The terminal uses the natural one-based notation, whereas Python indexes
    # and the cipher's internal permutation representation are zero-based.
    zero_based_key = []
    for i, value in enumerate(one_based_values):
        if value < 1:
            raise ValueError(f"{name} item {i} must be a positive integer, not {value}")
        zero_based_key.append(value - 1)
    return validate_permutation(tuple(zero_based_key), name)


def inverse_permutation(key: tuple[int, ...]) -> tuple[int, ...]:
    """Return the key that reverses ``key``.

        output[new_position] = input[key[new_position]]
    """
    validate_permutation(key)
    inverse_key = [0] * len(key)
    for new_position, old_position in enumerate(key):
        inverse_key[old_position] = new_position
    return tuple(inverse_key)

    # raise NotImplementedError("TODO(student): calculate the inverse permutation")


def pad_plaintext(
    plaintext: str,
    block_size: int,
    padding_character: str = PADDING_CHARACTER,
) -> tuple[str, int]:
    """Pad only the final block and return ``(padded_text, padding_length)``."""

    if type(plaintext) is not str:
        raise TypeError(f"Plaintext must be a string, not {type(plaintext).__name__}")
    if type(block_size) is not int:
        raise TypeError(f"Block size must be an integer, not {type(block_size).__name__}")
    if block_size <= 0:
        raise ValueError(f"Block size must be a positive integer, not {block_size}")
    if type(padding_character) is not str:
        raise TypeError(f"Padding character must be a string, not {type(padding_character).__name__}")
    if len(padding_character) != 1:
        raise ValueError(f"Padding character must be exactly one character, not {len(padding_character)}")

    # Calculate the number of characters needed to reach the next multiple of block_size
    current_length = len(plaintext)
    padding_needed = (block_size - (current_length % block_size)) % block_size

    # Append the required padding characters
    padded_text = plaintext + padding_character * padding_needed

    return padded_text, padding_needed


def text_to_grid(text_block: str, row_count: int, column_count: int) -> Grid:
    """Fill a grid row by row from one exactly sized text block."""

    if type(row_count) is not int:
        raise TypeError(f"Row count must be an integer, not {type(row_count).__name__}")
    if row_count <= 0:
        raise ValueError(f"Row count must be a positive integer, not {row_count}")
    if type(column_count) is not int:
        raise TypeError(f"Column count must be an integer, not {type(column_count).__name__}")
    if column_count <= 0:
        raise ValueError(f"Column count must be a positive integer, not {column_count}")
    expected_length = row_count * column_count
    if len(text_block) != expected_length:
        raise ValueError(f"Text block length {len(text_block)} does not match expected size {expected_length} (rows * columns)")

    grid = []
    for i in range(row_count):
        row = text_block[i * column_count:(i + 1) * column_count]
        grid.append(tuple(row))
    return tuple(grid)


def grid_to_text(grid: Grid) -> str:
    """Flatten a rectangular grid in row-major order."""

    if not grid:
        raise ValueError("Grid must not be empty")
    row_length = len(grid[0])
    if row_length == 0:
        raise ValueError("Grid rows must not be empty")
    for i, row in enumerate(grid):
        if len(row) != row_length:
            raise ValueError(f"Row {i} length {len(row)} does not match expected length {row_length}")
        for j, cell in enumerate(row):
            if type(cell) is not str or len(cell) != 1:
                raise ValueError(f"Cell at ({i}, {j}) must be a single character string, got {cell!r}")

    return "".join("".join(row) for row in grid)


def permute_rows(grid: Grid, row_key: tuple[int, ...]) -> Grid:
    """Reorder complete rows using the project's output-order convention."""

    validate_permutation(row_key)
    if len(row_key) != len(grid):
        raise ValueError(f"Row key length {len(row_key)} does not match grid row count {len(grid)}")

    new_grid = []
    for new_position in range(len(grid)):
        old_position = row_key[new_position]
        new_grid.append(grid[old_position])
    return tuple(new_grid)

    # raise NotImplementedError("TODO(student): apply the row permutation")


def permute_columns(grid: Grid, column_key: tuple[int, ...]) -> Grid:
    """Apply the same convention independently within every row."""

    validate_permutation(column_key)
    if len(column_key) != len(grid[0]):
        raise ValueError(f"Column key length {len(column_key)} does not match grid column count {len(grid[0])}")

    new_grid = []
    for row in grid:
        new_row = []
        for new_position in range(len(row)):
            old_position = column_key[new_position]
            new_row.append(row[old_position])
        new_grid.append(tuple(new_row))
    return tuple(new_grid)

    # raise NotImplementedError("TODO(student): apply the column permutation")


def encrypt(
    plaintext: str,
    row_key: tuple[int, ...],
    column_key: tuple[int, ...],
) -> tuple[str, TranspositionTrace]:
    """Encrypt one or more grids using rows first, then columns.

    Empty plaintext produces empty ciphertext and a trace containing no blocks.
    """
    if type(plaintext) is not str:
        raise TypeError(f"Plaintext must be a string, not {type(plaintext).__name__}")

    # Validate keys even when plaintext is empty. Otherwise an invalid key
    # could appear to work merely because no blocks happened to be processed.
    validated_row_key = validate_permutation(row_key, "Row key")
    validated_column_key = validate_permutation(column_key, "Column key")

    row_count = len(validated_row_key)
    column_count = len(validated_column_key)
    block_size = row_count * column_count
    padded_plaintext, padding_length = pad_plaintext(plaintext, block_size)

    ciphertext_blocks: list[str] = []
    block_traces: list[BlockTrace] = []

    for block_start in range(0, len(padded_plaintext), block_size):
        text_block = padded_plaintext[block_start:block_start + block_size]
        input_grid = text_to_grid(text_block, row_count, column_count)
        after_rows = permute_rows(input_grid, validated_row_key)
        after_columns = permute_columns(after_rows, validated_column_key)

        ciphertext_blocks.append(grid_to_text(after_columns))
        block_traces.append(
            BlockTrace(
                input_grid=input_grid,
                after_first_step=after_rows,
                after_second_step=after_columns,
            )
        )

    ciphertext = "".join(ciphertext_blocks)
    trace = TranspositionTrace(
        operation="encrypt",
        blocks=tuple(block_traces),
        padding_length=padding_length,
    )
    return ciphertext, trace


def decrypt(
    ciphertext: str,
    row_key: tuple[int, ...],
    column_key: tuple[int, ...],
    padding_length: int,
) -> tuple[str, TranspositionTrace]:
    """Reverse columns first, then rows, and remove exact recorded padding.

    Reversing the operation order is essential: inverse rows followed by
    inverse columns will generally not recover the plaintext.
    """
    if type(ciphertext) is not str:
        raise TypeError(f"Ciphertext must be a string, not {type(ciphertext).__name__}")
    if type(padding_length) is not int:
        raise TypeError(f"Padding length must be an integer, not {type(padding_length).__name__}")

    validated_row_key = validate_permutation(row_key, "Row key")
    validated_column_key = validate_permutation(column_key, "Column key")
    row_count = len(validated_row_key)
    column_count = len(validated_column_key)
    block_size = row_count * column_count

    if padding_length < 0 or padding_length >= block_size:
        raise ValueError(
            f"Padding length must be between 0 and {block_size - 1}, not {padding_length}"
        )
    if len(ciphertext) % block_size != 0:
        raise ValueError(
            f"Ciphertext length {len(ciphertext)} must be a multiple of block size {block_size}"
        )
    if padding_length > len(ciphertext):
        raise ValueError("Padding length cannot exceed ciphertext length")

    inverse_row_key = inverse_permutation(validated_row_key)
    inverse_column_key = inverse_permutation(validated_column_key)
    reconstructed_blocks: list[str] = []
    block_traces: list[BlockTrace] = []

    for block_start in range(0, len(ciphertext), block_size):
        ciphertext_block = ciphertext[block_start:block_start + block_size]
        ciphertext_grid = text_to_grid(ciphertext_block, row_count, column_count)

        # Encryption applies rows and then columns. Inverse operations must be
        # applied in the reverse order.
        after_inverse_columns = permute_columns(ciphertext_grid, inverse_column_key)
        after_inverse_rows = permute_rows(after_inverse_columns, inverse_row_key)

        reconstructed_blocks.append(grid_to_text(after_inverse_rows))
        block_traces.append(
            BlockTrace(
                input_grid=ciphertext_grid,
                after_first_step=after_inverse_columns,
                after_second_step=after_inverse_rows,
            )
        )

    padded_plaintext = "".join(reconstructed_blocks)
    if padding_length:
        expected_padding = PADDING_CHARACTER * padding_length
        if not padded_plaintext.endswith(expected_padding):
            raise ValueError("Decrypted text does not contain the claimed padding")
        plaintext = padded_plaintext[:-padding_length]
    else:
        plaintext = padded_plaintext

    trace = TranspositionTrace(
        operation="decrypt",
        blocks=tuple(block_traces),
        padding_length=padding_length,
    )
    return plaintext, trace


def compare_letter_frequencies(
    plaintext: str,
    ciphertext: str,
) -> dict[str, tuple[int, int]]:
    """Return ``letter -> (plaintext_count, ciphertext_count)`` for A-Z.

    For correctly transposed text, every pair should be equal because letters
    are rearranged rather than replaced. The non-letter padding character does
    not affect these counts. This is the required frequency-analysis result:
    ordinary single-letter frequency analysis reveals the same distribution
    but does not directly reveal the row and column permutations.
    """

    plaintext_counts = letter_counts(plaintext)
    ciphertext_counts = letter_counts(ciphertext)

    comparison: dict[str, tuple[int, int]] = {}
    for letter, plaintext_count in plaintext_counts.items():
        comparison[letter] = (plaintext_count, ciphertext_counts[letter])

    return comparison
