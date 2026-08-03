# Implementation plan

## Phase 1: foundations and classical ciphers

- Finish and test PKCS#7, byte/block conversion, XOR, and modular-arithmetic helpers.
- Implement substitution key validation, encryption/decryption, frequency ranking, and a bounded
  brute-force demonstration.
- Implement double transposition with explicit row/column permutation semantics, visible grids, and
  unambiguous padding removal.

Acceptance: round trips preserve punctuation/case according to documented rules, invalid keys fail
clearly, and fixed examples are tested.

## Phase 2: block ciphers

- Implement raw DES block/key schedule, then padded text wrappers.
- Implement raw AES-128 transforms/key expansion, then padded text wrappers.
- Return structured traces so the UI can display all round keys without printing inside core logic.

Acceptance: official known-answer vectors pass; inverse transforms and multi-block round trips pass.

## Phase 3: public-key algorithms

- Implement Miller-Rabin, extended Euclid, prime generation, key generation, block encoding, and
  textbook RSA operations.
- Implement trial division/Pollard-rho for intentionally small factorization demonstrations.
- Implement curve validation, point membership, addition, doubling, scalar multiplication, point
  enumeration, subgroup/order checks, and ECDH.

Acceptance: RSA block bounds are enforced; factorization reconstructs the toy modulus; ECC handles
the point at infinity and matching ECDH shared points.

## Phase 4: CLI, experiments, and report evidence

- Connect each submenu to pure core functions.
- Record repeat count, input/key sizes, mean, median, standard deviation, and environment metadata.
- Export machine-readable CSV and a Markdown comparison table under `results/`.
- Add security analysis and screenshots only after correctness tests pass.

