# Guided implementation of DES

Implement DES in [`symmetric/des.py`](../symmetric/des.py). The standard tables have already been
transcribed into [`symmetric/des_tables.py`](../symmetric/des_tables.py); do not casually edit them.
Search `symmetric/des.py` for `TODO(student)` and work in the order below.

Primary references:

- [NIST FIPS 46-3: Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-17: DES validation tests and sample round outputs](https://www.nist.gov/publications/modes-operation-validation-system-movs-requirements-and-procedures)

FIPS 46-3 is withdrawn and DES is obsolete. This implementation is strictly educational.

## Corrections and refinements to the theory notes

Most of the supplied understanding is correct. These details need adjustment:

1. **Supplied key versus effective key:** standard DES accepts a 64-bit key. Eight positions are
   parity bits, leaving 56 active bits. PC-1 selects/reorders the active bits and produces `C0 || D0`.
   It is accurate to call DES's security key length 56 bits, but the raw API should accept eight bytes.
2. **PC-2 is a selection/permutation:** it selects 24 positions from `C_i` and 24 from `D_i`, so eight
   of the 56 positions are absent. Calling this “discard four bits from each” is numerically true but
   can sound like simple truncation; PC-2 selects specific reordered positions.
3. **C and D remain separate:** after producing `K_i`, retain `C_i` and `D_i` separately and rotate
   those values for the next round.
4. **Preoutput order:** after applying the recurrence for all 16 rounds, form `R16 || L16`, then apply
   `IP^-1`.
5. **Decryption key schedule:** do not write a separate right-shift key schedule. Generate `K1..K16`
   once with the normal left rotations, then supply them to the same Feistel loop in reverse order.
   A carefully designed on-the-fly hardware schedule can move backward, but “start at C0/D0 and
   right-shift each decryption round” is not generally equivalent and is an avoidable source of bugs.
6. **S-box addressing:** for each six-bit chunk `b1 b2 b3 b4 b5 b6`, row is `b1b6` and column is
   `b2b3b4b5`. The eight four-bit results are concatenated before P.

## Precise encryption summary

```text
8-byte plaintext block
  -> IP
  -> split as L0 || R0

8-byte supplied key
  -> PC-1 (64 -> 56, parity positions omitted)
  -> split as C0 || D0
  -> for rounds i=1..16:
       C_i = left_rotate(C_i-1, scheduled amount)
       D_i = left_rotate(D_i-1, scheduled amount)
       K_i = PC-2(C_i || D_i)              # 48 bits

for rounds i=1..16:
  expanded = E(R_i-1)                       # 32 -> 48
  mixed    = expanded XOR K_i               # 48
  selected = S1..S8(mixed)                  # 48 -> 32
  f_output = P(selected)                     # 32 -> 32
  L_i      = R_i-1
  R_i      = L_i-1 XOR f_output

preoutput = R16 || L16
ciphertext = IP^-1(preoutput)                # 8 bytes
```

## Precise decryption summary

```text
Generate K1..K16 exactly as for encryption.

8-byte ciphertext block
  -> IP
  -> split as L0 || R0 for this invocation

Run the identical Feistel loop using:
  K16, K15, ..., K1

preoutput = R16 || L16
plaintext = IP^-1(preoutput)
```

The local variable names `L0` and `R0` during decryption refer to halves of `IP(ciphertext)`, not the
original encryption `L0` and `R0`. Reversing the keys is what makes the same recurrence undo DES.

## What is actually hard-coded?

Only these standardized constants:

- IP and `IP^-1`;
- expansion E and permutation P;
- PC-1, PC-2, and the 16 shift amounts;
- eight S-box tables;
- the weak/semi-weak key list used by key generation.

The permutation engine, rotations, key schedule, S-box addressing, Feistel recurrence, byte
conversion, padding, encryption, and decryption are algorithms you must implement—not hard-coded
answers.

## Stage 1: bit foundations

Implement:

1. `_require_exact_bytes`
2. `_permute`
3. `_rotate_left_28`

Then enable the corresponding tests in [`tests/test_des.py`](../tests/test_des.py).

Use integers internally. Keep values in bytes only at the public block boundary. Integer code makes
bit widths explicit and avoids building thousands of temporary `'0'`/`'1'` strings.

## Stage 2: parity and automatic key generation

Implement:

1. `has_odd_parity`
2. `set_odd_parity`
3. `is_weak_key`
4. `generate_key`

Generated keys must use `secrets.token_bytes(8)`, have odd parity in every byte, and avoid the weak
and semi-weak list. Raw block encryption should still accept weak keys because conformance tests can
intentionally use one.

## Stage 3: key schedule

Implement:

1. `build_key_schedule`
2. `expand_key`

For each round, save `C_i`, `D_i`, shift amount, and `K_i` in `DESKeyRound`. The project explicitly
requires displaying all 16 round keys, so traceability is part of the design rather than terminal
printing inside the core algorithm.

## Stage 4: DES round function

Implement:

1. `_sbox_substitute`
2. `_feistel`

Check widths at every boundary:

```text
R: 32 -> E(R): 48 -> XOR K: 48 -> S-boxes: 32 -> P: 32
```

## Stage 5: raw block encryption and decryption

Implement:

1. `_process_block`
2. `encrypt_block`
3. `decrypt_block`

Do not proceed until the NIST known-answer vectors pass. An encryption/decryption round trip alone
is insufficient: the same bug in both directions can still round-trip successfully.

Run:

```bash
python3 -m unittest tests.test_des -v
```

## Stage 6: arbitrary text and padding

Implement [`pkcs7_pad`](../common/padding.py) and [`pkcs7_unpad`](../common/padding.py), then implement
`encrypt_ecb` and `decrypt_ecb`.

The eventual CLI should:

1. encode plaintext with UTF-8;
2. automatically generate and display the 8-byte key as 16 hexadecimal digits;
3. PKCS#7-pad to 8-byte blocks;
4. display ciphertext as hexadecimal;
5. display all `K1..K16` as 12 hexadecimal digits each;
6. accept hexadecimal ciphertext/key for decryption;
7. display recovered UTF-8 text and intermediate rounds.

ECB is acceptable here only as a transparent coursework demonstration. Clearly label that it leaks
repeated-block patterns and is not appropriate for protecting real information.

## Stage 7: terminal menu

Only after every DES test passes, create `cli/des_menu.py`:

```text
DES

1. Generate key
2. Encrypt text with an auto-generated key
3. Decrypt hexadecimal ciphertext
4. Display all round keys / round trace
5. Return to main menu
```

Connect it to main-menu option 3 and mark DES implemented only then.

