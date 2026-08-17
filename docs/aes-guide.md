# Understanding and guided implementation of AES-128

Implement AES-128 in [`symmetric/aes.py`](../symmetric/aes.py). The fixed S-boxes, round constants,
and MixColumns matrices are already transcribed into
[`symmetric/aes_tables.py`](../symmetric/aes_tables.py); do not casually edit them. Work through the
TODO functions in the stages below.

Primary references:

- [NIST FIPS 197-upd1: Advanced Encryption Standard](https://doi.org/10.6028/NIST.FIPS.197-upd1)
- [NIST AES-128 examples with intermediate values](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf)
- [NIST SP 800-38A: block-cipher modes](https://doi.org/10.6028/NIST.SP.800-38A)

## 1. Scope decision for this project

The assignment says “AES” but does not select AES-128, AES-192, or AES-256. This project implements
**AES-128** first:

| Property | AES-128 value |
|---|---:|
| Data block | 128 bits = 16 bytes |
| Original key | 128 bits = 16 bytes |
| State | 4 rows x 4 columns of bytes |
| Rounds | 10 |
| Expanded words | 44 words, 4 bytes each |
| Round keys | 11 keys: K0 through K10 |

AES-192 and AES-256 keep the 128-bit block size but use longer keys and 12 or 14 rounds. They are
out of scope unless the instructor asks for them.

## 2. The biggest conceptual difference from DES

DES is a Feistel network: it divides a block into left/right halves, transforms the right half, XORs
with the left half, and swaps roles. AES does none of that.

AES is a **substitution-permutation network**. It treats the complete 16-byte block as one state and
repeatedly applies reversible transformations to the whole state:

```text
SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
```

Consequences:

- there are no `L` and `R` halves;
- there is no final `R || L` swap;
- decryption requires inverse transformations, not merely reversed subkeys in the encryption loop;
- the AES block is always 128 bits, even for AES-192 and AES-256.

## 3. The 4 x 4 state: understand this before coding

AES stores the 16 input bytes **by columns**. If the input block is:

```text
00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
```

the state is:

```text
       column 0  column 1  column 2  column 3
row 0     00        44        88        cc
row 1     11        55        99        dd
row 2     22        66        aa        ee
row 3     33        77        bb        ff
```

The formula is:

```text
state[row][column] = input[row + 4 * column]
```

The first four consecutive input bytes form the first **column**, not the first row. A row-major
state can still encrypt and decrypt itself consistently yet fail every official vector, so a simple
round trip is not sufficient evidence of correctness.

## 4. The four encryption transformations

### 4.1 SubBytes: nonlinear byte substitution

Every state byte is independently replaced through the standard 256-entry S-box:

```text
new_byte = S_BOX[old_byte]
```

For example, `S_BOX[0x53] = 0xed`. In the printed 16 x 16 table, the high nibble `5` identifies the
row and the low nibble `3` identifies the column. In code, a flat 256-entry tuple makes the byte
itself the index.

The S-box is not an arbitrary secret table and is not derived from the user key. Mathematically, it
is built from a multiplicative inverse in `GF(2^8)` followed by an affine transformation. For this
project, using the standardized table is appropriate; implementing the round logic is still “from
scratch.” `InvSubBytes` uses the inverse permutation table.

Purpose: provide **nonlinearity/confusion** so AES is not just a system of linear XORs and byte
movements.

### 4.2 ShiftRows: move bytes between columns

Shift each state row cyclically to the left by its row number:

```text
row 0: left 0 (unchanged)
row 1: left 1
row 2: left 2
row 3: left 3
```

`InvShiftRows` rotates those rows right by the same amounts.

Purpose: bytes that originally occupied one column are moved into different columns so the next
MixColumns step spreads their influence further.

### 4.3 MixColumns: finite-field matrix multiplication

Each column is multiplied independently by this fixed matrix:

```text
[02 03 01 01]
[01 02 03 01]
[01 01 02 03]
[03 01 01 02]
```

The arithmetic is in `GF(2^8)`, not ordinary integer arithmetic:

- addition is XOR;
- multiplication is polynomial multiplication reduced modulo
  `x^8 + x^4 + x^3 + x + 1`;
- multiplying by `{02}` is `XTIMES`;
- multiplying by `{03}` is `XTIMES(value) XOR value`.

For a column `[s0, s1, s2, s3]`, the first output byte is:

```text
({02} * s0) XOR ({03} * s1) XOR s2 XOR s3
```

`InvMixColumns` uses coefficients `0e`, `0b`, `0d`, and `09`. A general GF multiplication helper
can implement both directions cleanly.

Purpose: provide **diffusion** within every column. Together with ShiftRows, influence spreads
across the state over successive rounds.

### 4.4 AddRoundKey: XOR with 16 key bytes

XOR the complete state with the current 16-byte round key. Each key word corresponds to one state
column. XOR is its own inverse, so decryption also uses AddRoundKey.

This is the only round transformation that directly incorporates secret key material.

## 5. Exact AES-128 encryption sequence

AES-128 uses ten rounds but AddRoundKey is called eleven times:

```text
16-byte plaintext
  -> convert to column-major state

Initial step (sometimes called round 0):
  state = AddRoundKey(state, K0)

Rounds 1 through 9:
  state = SubBytes(state)
  state = ShiftRows(state)
  state = MixColumns(state)
  state = AddRoundKey(state, Kround)

Round 10:
  state = SubBytes(state)
  state = ShiftRows(state)
  state = AddRoundKey(state, K10)
  # MixColumns is deliberately omitted

-> serialize state by columns
-> 16-byte ciphertext
```

The final round still has SubBytes, ShiftRows, and AddRoundKey. Only MixColumns is omitted.

## 6. AES-128 key expansion

The original 16-byte key becomes four 4-byte words:

```text
K0 = w0 || w1 || w2 || w3
```

Generate `w4` through `w43`. Normally:

```text
w[i] = w[i - 4] XOR w[i - 1]
```

At every multiple of four, transform the previous word first:

```text
temp = RotWord(w[i - 1])      # [a0,a1,a2,a3] -> [a1,a2,a3,a0]
temp = SubWord(temp)          # S-box each byte
temp[0] ^= Rcon[i // 4]
w[i] = w[i - 4] XOR temp
```

The ten round constants begin:

```text
01 02 04 08 10 20 40 80 1b 36
```

Group each four consecutive words into a round key:

```text
K0  = w0  || w1  || w2  || w3
K1  = w4  || w5  || w6  || w7
...
K10 = w40 || w41 || w42 || w43
```

Important corrections to common misconceptions:

- the round keys are derived, not independently random;
- K0 is the original AES-128 key and must be displayed as a round key;
- AES has no DES parity bits and no standard list of weak keys to reject;
- key expansion uses the same AES S-box as SubBytes;
- Rcon affects only the first byte of `temp`.

## 7. Exact AES-128 decryption sequence

Generate K0 through K10 exactly as for encryption. Do not invent a separate reverse key expansion.

The standard inverse cipher is:

```text
16-byte ciphertext
  -> convert to column-major state

Initial inverse step:
  state = AddRoundKey(state, K10)

For round numbers 9 down to 1:
  state = InvShiftRows(state)
  state = InvSubBytes(state)
  state = AddRoundKey(state, Kround)
  state = InvMixColumns(state)

Final inverse round:
  state = InvShiftRows(state)
  state = InvSubBytes(state)
  state = AddRoundKey(state, K0)
  # InvMixColumns is omitted

-> serialize state by columns
-> 16-byte plaintext
```

This order often looks surprising. It is the order specified for the standard `INVCIPHER`. NIST
also defines an “equivalent inverse cipher” with transformed round keys, but that optimization would
add unnecessary complexity here. Implement the standard inverse cipher above.

## 8. What is hard-coded and what you implement

Hard-coded standardized constants:

- `S_BOX` and `INV_S_BOX`;
- the ten AES-128 round constants;
- MixColumns and InvMixColumns matrices.

Algorithms you implement:

- state validation and column-major conversion;
- random key generation;
- RotWord, SubWord, word XOR, and key expansion;
- SubBytes and inverse;
- ShiftRows and inverse;
- finite-field multiplication;
- MixColumns and inverse;
- AddRoundKey;
- encryption/decryption round sequences;
- tracing, padding, and multi-block wrappers.

## 9. Guided coding stages

### Stage 1: state and input foundations

Implement in this order:

1. `_require_exact_bytes`
2. `_validate_state`
3. `_bytes_to_state`
4. `_state_to_bytes`

Then enable only the `AESStateTests` tests. Do not proceed until the exact displayed state for
`001122...eeff` matches the FIPS column-major arrangement.

### Stage 2: key generation and expansion

Implement:

1. `generate_key`
2. `_xor_words`
3. `_rot_word`
4. `_sub_word`
5. `expand_key`

The FIPS Appendix A.1 test pins K1 and K10. Checking only that 11 keys were produced is not enough.

### Stage 3: byte substitution and row movement

Implement:

1. `_sub_bytes`
2. `_inv_sub_bytes`
3. `_shift_rows`
4. `_inv_shift_rows`

Every forward/inverse pair must restore arbitrary valid states, and the official intermediate values
must also match.

### Stage 4: finite-field arithmetic and column mixing

Implement:

1. `_xtime`
2. `_gf_multiply`
3. `_mix_single_column`
4. `_mix_columns`
5. `_inv_mix_columns`

Do not use normal integer multiplication followed by `% 256`; that is not AES field arithmetic.

### Stage 5: round-key addition

Implement `_add_round_key`. Reuse the established state mapping rather than inventing a new key
layout. Applying the same round key twice must restore the starting state.

### Stage 6: raw block encryption

Implement `encrypt_block`, including `AESStageTrace` entries. Enable the FIPS known-answer test:

```text
Key:        000102030405060708090a0b0c0d0e0f
Plaintext:  00112233445566778899aabbccddeeff
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
```

Do not rely only on encryption/decryption round trips; mirrored errors can cancel each other.

### Stage 7: raw block decryption

Implement `decrypt_block` using the standard inverse sequence. Confirm both the FIPS vector and the
NIST SP 800-38A ECB block vector.

### Stage 8: arbitrary UTF-8 text

Reuse [`common/padding.py`](../common/padding.py), which already implements strict PKCS#7 padding.
Implement `encrypt_ecb` and `decrypt_ecb` with 16-byte blocks.

ECB is used only because it makes independent AES blocks easy to inspect in a coursework demo. It
reveals repeated-block patterns and provides no authentication, so label it unsuitable for real
data. The raw AES implementation can later be used inside a safer authenticated mode, but that is
outside this assignment's current scope.

### Stage 9: terminal submenu

Only after every AES test passes, create `cli/aes_menu.py`:

```text
AES-128

1. Generate key and display K0 through K10
2. Encrypt text with an auto-generated key
3. Decrypt hexadecimal ciphertext
4. Display round keys / inspect one-block trace
5. Return to main menu
```

Connect it to main-menu option 4 and mark AES-128 implemented only then.

## 10. Frequent AES mistakes to avoid

1. Filling the state by rows instead of columns.
2. Calling the initial AddRoundKey “round 1” and ending with the wrong key.
3. Running MixColumns during round 10.
4. Rotating state columns in ShiftRows instead of rotating rows.
5. Mixing rows instead of columns.
6. Using ordinary integer multiplication in MixColumns.
7. Applying Rcon to every generated key-schedule word.
8. Treating AES-128 as 128-bit blocks but accidentally accepting 32-character text rather than 16
   bytes.
9. Decrypting with the encryption transformation order and only reversing keys, as one can do with
   DES's Feistel structure.
10. Claiming ECB encryption is secure merely because AES itself is strong.

## 11. How to run the staged tests

At the beginning, only the fixed-table tests run; implementation tests are deliberately skipped.
After completing a stage, remove the matching `@unittest.skip` decorator in
[`tests/test_aes.py`](../tests/test_aes.py), then run:

```bash
python3 -m unittest tests.test_aes -v
```

After each milestone, also run the full project suite:

```bash
python3 -m unittest discover -s tests -v
```
