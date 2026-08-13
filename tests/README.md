# Test strategy

Add tests beside `test_scaffold.py` as each module is implemented:

- `test_substitution.py`: permutation validation, inverse mapping, round trips, reduced brute force,
  and frequency analysis;
- `test_double_transposition.py`: key parsing, fixed grids, inverse keys, padding, multi-block
  round trips, and preserved frequencies;
- `test_des.py`: fixed-table integrity, NIST known-answer vectors, key schedule, parity, PKCS#7,
  trace values, and multi-block round trips;
- `test_aes.py`: FIPS-197 AES-128 key expansion and cipher/inverse-cipher examples;
- `test_rsa.py`: number-theory identities, key sizes, block bounds, Unicode round trips, toy attack;
- `test_ecc.py`: curve discriminant, all group-law branches, point enumeration/order, ECDH equality;
- `test_performance.py`: validation of repetitions and summary shape (not speed thresholds).

Known-answer vectors must record their authoritative source in a nearby comment or the final report.
