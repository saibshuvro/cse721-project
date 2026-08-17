# CSE721 Cryptography Project

An educational Python command-line project for implementing, inspecting, and comparing:

- monoalphabetic substitution and double-transposition ciphers;
- DES and AES-128;
- RSA with a small-key factorization demonstration;
- elliptic-curve arithmetic and ECDH.

The implementation must not use cryptographic libraries for core operations. It is for coursework
and must not be used to protect real data.

## Current status

The monoalphabetic substitution, Double Transposition, DES, AES-128, and RSA components are
implemented, tested, and available from main-menu options 1 through 5. ECC/ECDH has a guided TODO
template and staged tests; comparative performance analysis remains scaffolded.

## Run

Python 3.10 or newer is required.

```bash
python3 main.py
python3 main.py --list
python3 -m unittest discover -s tests -v
```

No third-party runtime packages are required. A virtual environment is still recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
```

## Layout

```text
.
├── main.py                    # CLI entry point
├── classical/                 # substitution, frequency analysis, transposition
├── symmetric/                 # DES and AES-128
├── public_key/                # RSA, factorization, ECC, ECDH
├── common/                    # shared padding and encoding helpers
├── analysis/                  # repeatable timing and security comparison
├── tests/                     # unit, known-answer, and round-trip tests
├── docs/                      # requirement decisions and implementation plan
└── results/                   # generated timing tables/plots (ignored by Git)
```

See [docs/requirements-analysis.md](docs/requirements-analysis.md) for the critical requirements
review and explicit assumptions, and [docs/implementation-plan.md](docs/implementation-plan.md) for
the recommended build order and acceptance criteria.

## Definition of done

Each implementation should provide:

1. encryption/decryption or key-agreement correctness;
2. required intermediate values (grids, round keys, points, or attack output);
3. authoritative known-answer tests where applicable;
4. round-trip, invalid-input, and edge-case tests;
5. repeated performance measurements using `time.perf_counter_ns()`;
6. a short security explanation that distinguishes educational behavior from secure practice.
