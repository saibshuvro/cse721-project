# Critical requirements analysis

This document reconciles `project gpt.txt` with `CSE721 Project requirements.pdf`. The PDF is treated
as the authoritative specification; the text file is an implementation recommendation.

## What the proposal gets right

- A modular Python CLI is the lowest-risk way to satisfy the selectable-algorithm interface.
- DES, AES, RSA, and ECC should be implemented as separate modules.
- Full substitution-key brute force (`26!`) and enumeration of a production-size elliptic curve are
  computationally infeasible; bounded educational demonstrations are needed.
- RSA factorization must use a deliberately small key, independently of normal key generation.
- Timing should be repeated and summarized instead of reporting a single noisy measurement.

## Gaps and ambiguities resolved by this scaffold

1. **Substitution brute force is explicitly required in the overview.** The implementation will offer
   exhaustive search only for a reduced alphabet/restricted key space and frequency analysis for the
   full 26-letter cipher. The UI and report must not imply that all `26!` keys were searched.
2. **Double-transposition frequency analysis is requested in the detailed requirements.** A
   transposition preserves symbol counts, so the output will compare plaintext and ciphertext
   frequency tables and explain why ordinary frequency analysis does not recover the permutation.
3. **Modes, encodings, and padding are unspecified.** DES and AES will expose raw single-block
   functions for known-answer tests. Text demos will use UTF-8 plus PKCS#7 padding. The initial
   educational multi-block mode is ECB so intermediate blocks remain visible; the report must label
   ECB as pattern-leaking and unsuitable for real security.
4. **DES key generation is ambiguous.** Generate eight random bytes, set odd parity, reject known
   weak/semi-weak keys, and clearly state that only 56 bits are effective.
5. **AES variants are unspecified.** Implement AES-128 first (16-byte key, 10 rounds, 11 displayed
   round keys). AES-192/256 are out of scope unless the instructor confirms otherwise.
6. **RSA text encoding is unspecified.** Use length-safe integer blocks strictly smaller than `n`.
   The coursework path will demonstrate textbook RSA but label it deterministic and insecure; it is
   not a substitute for OAEP. Normal demo choices may accept 512/1024 bits as requested, while the
   report must state that both are obsolete for real deployment.
7. **“List of all Ps” is ambiguous.** Interpret it as listing every affine point plus the point at
   infinity on a small educational curve. The default curve is `p=17, a=2, b=2`; `G` and its order
   `n` must be validated rather than assumed.
8. **ECDH inputs `a, b` conflict with curve coefficients named `a, b`.** The CLI will call participant
   private scalars `alice_private` and `bob_private` and reserve `a`, `b` for curve coefficients.
9. **Performance comparisons can be misleading.** Compare like operations and record message size,
   key size, repetitions, Python version, and platform. Separate key generation from encryption,
   decryption, and attacks.

## Security boundary

All code is educational and unaudited. “From scratch” implementations are useful for exposing the
mathematics but are likely variable-time and vulnerable to side channels. They must never be
presented as production cryptography.

