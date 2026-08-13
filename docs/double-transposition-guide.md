# Where to write the double transposition cipher

Write the second classical algorithm in
[`classical/double_transposition.py`](../classical/double_transposition.py). Search for
`TODO(student)` and implement one small function at a time.

## Assumption used by this project

The PDF does not define its two permutation keys precisely. This project documents the following
reasonable interpretation:

- first permutation key = row order;
- second permutation key = column order;
- user input is one-based, such as `3 1 2`;
- internal tuples are zero-based, so that input becomes `(2, 0, 1)`;
- `output[new_position] = input[key[new_position]]`.

Do not change this convention halfway through the implementation. Most transposition bugs come from
using different key directions in encryption and decryption.

## 1. Implement key handling

1. `validate_permutation`
2. `parse_permutation_key`
3. `inverse_permutation`

After completing them, remove the corresponding skips from
[`tests/test_double_transposition.py`](../tests/test_double_transposition.py) and run the tests.

## 2. Implement grid foundations

1. `pad_plaintext`
2. `text_to_grid`
3. `grid_to_text`

The number of rows comes from the row-key length and the number of columns comes from the column-key
length. Their product is one block's capacity. Only the final block is padded with `~`, and the exact
padding length is recorded.

Never remove padding with `rstrip("~")`: legitimate plaintext may end in `~`. Remove exactly the
recorded number of characters after verifying those positions contain the padding character.

## 3. Implement the two permutations

1. `permute_rows`
2. `permute_columns`

Use this fixed example while debugging:

```text
Input grid (2 rows × 3 columns):
A B C
D E F

Row key:    2 1       -> internal (1, 0)
After rows:
D E F
A B C

Column key: 3 1 2     -> internal (2, 0, 1)
After columns:
F D E
C A B

Ciphertext: FDECAB
```

## 4. Implement encryption and decryption

Implement `encrypt`, then `decrypt`. Encryption order is:

```text
plaintext -> padded grids -> row permutation -> column permutation -> ciphertext
```

Decryption must reverse both the direction and order:

```text
ciphertext -> inverse columns -> inverse rows -> remove exact padding -> plaintext
```

The template supports multiple grids so the CLI is not limited to very short messages.

## 5. Implement the required frequency analysis

Implement `compare_letter_frequencies` by reusing `letter_counts`. A transposition cipher does not
replace letters, so plaintext and ciphertext counts should match exactly. Explain that the preserved
distribution is useful to an attacker but does not itself reveal the two permutation keys.

## 6. Run tests gradually

```bash
python3 -m unittest tests.test_double_transposition -v
```

After every double-transposition test is enabled and passes:

```bash
python3 -m unittest discover -s tests -v
```

## 7. Terminal submenu

The completed algorithm is connected through `cli/double_transposition_menu.py` with:

```text
Double Transposition Cipher

1. Encrypt
2. Decrypt
3. Frequency comparison
4. Return to main menu
```

It displays the parsed keys, padding length, every intermediate grid, ciphertext, reconstructed
grid, and recovered plaintext. It catches invalid terminal input and main-menu option 2 opens it.
