# Where to write the monoalphabetic substitution cipher

Write the first required algorithm in
[`classical/substitution.py`](../classical/substitution.py). It is a guided template: search for
`TODO(student)` and implement the functions in the following order.

## Understanding the key

Use a 26-letter permutation such as:

```text
Plain alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ
Key:            QWERTYUIOPASDFGHJKLZXCVBNM
```

The positions define the mapping: A encrypts to Q, B to W, C to E, and Z to M. This is not a
password and not a Caesar shift. Every A-Z letter must occur exactly once so that the mapping can be
reversed during decryption.

## 1. Key handling and core cipher

1. `validate_key` — check and normalize the 26-letter permutation.
2. `build_encryption_mapping` — construct plaintext -> ciphertext pairs.
3. `build_decryption_mapping` — reverse those pairs.
4. `_translate_character` — translate one letter while preserving case/non-letters.
5. `encrypt` — apply the forward mapping to the whole plaintext.
6. `decrypt` — apply the inverse mapping to the whole ciphertext.

Do not put `input()` or `print()` inside these functions. They receive values and return results; the
terminal submenu will handle interaction only after the algorithm tests pass.

## 2. Brute-force demonstration

A full permutation key space contains:

```text
26! = 403,291,461,126,605,635,584,000,000 keys
```

Do not attempt to generate that key space. Implement `validate_reduced_alphabet` and
`brute_force_reduced` to exhaust a toy alphabet such as `ABCDE`. This honestly demonstrates the
attack and its factorial growth. With eight letters there are already `8! = 40,320` candidates.

In the report, distinguish clearly between:

- an exhaustive demonstration on a reduced alphabet; and
- heuristic frequency analysis against the full 26-letter cipher.

## 3. Frequency analysis

Write the full-alphabet analysis in
[`classical/frequency_analysis.py`](../classical/frequency_analysis.py):

1. `letter_counts`
2. `ranked_letters`
3. `letter_percentages`
4. `suggest_english_mapping`
5. `apply_partial_mapping`

The suggestion maps the most frequent ciphertext letters to the usual English frequency order
`ETAOIN...`. It is only an initial guess. Short messages, names, and unusual vocabulary may produce
incorrect mappings, so label the output “suggested mapping,” not “recovered key.”

## 4. Tests

Tests are in [`tests/test_substitution.py`](../tests/test_substitution.py). They begin skipped so the
whole project stays green while you work. After completing a function, remove the corresponding
`@unittest.skip` line and run:

```bash
python3 -m unittest tests.test_substitution -v
```

When all substitution tests pass, run everything:

```bash
python3 -m unittest discover -s tests -v
```

## 5. Terminal submenu (only after logic tests pass)

Connect option 1 in `main.py` to a submenu that can:

1. accept plaintext and a 26-letter key;
2. display the full A->key-letter mapping;
3. display ciphertext and decrypted text;
4. run the reduced-alphabet brute-force demonstration;
5. display frequency counts, percentages, ranked letters, a suggested mapping, and its preview.

Keeping interface code last prevents `input()`/`print()` behavior from hiding algorithm errors.
