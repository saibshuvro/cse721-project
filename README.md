# CSE721 Cryptography Project

A completed educational Python command-line application that implements, inspects, and compares
classical, symmetric-key, and public-key cryptographic algorithms without using cryptographic
libraries for their core operations.

The project covers:

- general monoalphabetic substitution with reduced-alphabet brute force and frequency analysis;
- row-and-column double transposition with frequency preservation analysis;
- DES with its key schedule, round traces, PKCS#7 padding, and an ECB text demonstration;
- AES-128 with key expansion, transformation traces, PKCS#7 padding, and an ECB text demonstration;
- textbook RSA with key generation, text blocking, encryption/decryption, and a bounded toy
  factorization attack;
- elliptic-curve arithmetic and ECDH over a small inspectable curve; and
- repeatable comparative performance measurements and structured security analysis.

## Project status

The planned coursework scope is complete. All seven main-menu components are implemented, connected
to the terminal interface, and covered by automated tests. No additional algorithms or graphical/web
interface are planned; future changes should be limited to bug fixes, documentation corrections, and
report evidence.

Run the current verification suite with:

```bash
python3 -m unittest discover -s tests -v
```

## Requirements and installation

- Python 3.10 or newer
- No third-party runtime packages

The implementations use only the Python standard library. Python big integers, basic mathematics,
and the `secrets` module are used where permitted by the assignment.

Run directly from the project directory:

```bash
python3 main.py
python3 main.py --list
```

An editable installation is optional:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
cse721-crypto
```

## Main menu

| Option | Component | Included operations |
|---:|---|---|
| 1 | Substitution Cipher | Encrypt, decrypt, reduced-alphabet brute force, frequency analysis |
| 2 | Double Transposition Cipher | Encrypt, decrypt, compare preserved letter frequencies |
| 3 | DES | Generate key, show all round keys, encrypt/decrypt text, inspect a block trace |
| 4 | AES-128 | Generate key, show K0–K10, encrypt/decrypt text, inspect transformation traces |
| 5 | RSA | Generate 512/1024-bit coursework keys, encrypt/decrypt text, run toy factorization |
| 6 | ECC / ECDH | Validate parameters, list points, inspect point order, generate keys, demonstrate ECDH |
| 7 | Performance & Security Analysis | Run benchmarks, display security comparison, export reports |
| 8 | Exit | Close the application |

## Performance and security analysis

Select main-menu option 7 to run either benchmark profile:

| Profile | Purpose | Cases | Normal repetitions | Slow-operation repetitions |
|---|---|---:|---:|---:|
| Quick | Development checks and live demonstrations | 40 | 5 | 1 |
| Full | Final report-quality experiment | 66 | 30 | 5 |

Both profiles cover every cryptographic component and both 512- and 1024-bit RSA key sizes. The full
profile additionally uses more message and reduced-alphabet sizes. Setup, key preparation for timed
message operations, terminal output, and warm-up calls are excluded from recorded samples. Results
include the mean, median, sample standard deviation, repetition count, input size, key/parameter
description, Python version, and platform information.

After a quick or full run, choose the export option to generate:

```text
results/
├── performance.csv
├── performance.md
└── security_analysis.md
```

Run the full profile immediately before exporting final submission evidence. Generated files under
`results/` are ignored by Git by default, while `results/.gitkeep` preserves the directory.

## Security boundary

This repository is for coursework and must not be used to protect real data.

- Classical substitution and transposition ciphers leak language or structural information.
- Single DES has only 56 effective key bits and is obsolete.
- The DES and AES text wrappers use ECB so independent blocks and round traces remain visible; ECB
  leaks repeated-block patterns and the wrappers provide no authentication.
- The RSA text interface is deterministic textbook RSA without OAEP. The assignment's 512/1024-bit
  sizes and the separate factorization example are educational only.
- The default ECC group has order 19 and only 18 possible private scalars. The ECDH demonstration
  returns a raw x-coordinate without a KDF or peer authentication.
- The from-scratch Python implementations are variable-time and are not hardened against side-channel
  attacks.

The generated security report separates algorithm design, project parameters, demonstrated attacks,
implementation limitations, and real-world conclusions. It also includes links to the relevant NIST
and RFC sources.

## Project layout

```text
.
├── main.py                    # Main CLI entry point and component registry
├── cli/                       # Interactive submenus for all seven options
├── classical/                 # Substitution, frequency analysis, double transposition
├── symmetric/                 # DES, AES-128, and fixed algorithm tables
├── public_key/                # RSA, toy factorization, ECC, and ECDH
├── common/                    # Shared PKCS#7 padding helper
├── analysis/                  # Timing, benchmark cases/suites, reporting, security analysis
├── tests/                     # Unit, known-answer, round-trip, CLI, and reporting tests
├── docs/                      # Guided implementation notes and requirement decisions
├── results/                   # On-demand CSV/Markdown reports, ignored by Git
├── pyproject.toml             # Package metadata and terminal entry point
├── requirements.txt           # Documents the zero third-party dependency policy
├── CSE721 Project requirements.pdf
└── project gpt.txt
```

## Testing

The test suite covers:

- invalid inputs, boundary conditions, and round trips;
- monoalphabetic mappings, heuristic frequency analysis, and reduced brute force;
- transposition grids, permutations, padding, and preserved frequencies;
- official DES and AES known-answer values and intermediate stages;
- RSA number theory, key generation, text blocking, and toy factorization;
- ECC group-law branches, point enumeration/order, validation, and matching ECDH secrets;
- benchmark statistics, case selection, quick/full suite execution, and progress handling;
- CSV/Markdown report generation and structured security analysis; and
- every interactive submenu and main-menu dispatch path.

Tests assert correctness and report structure, not fixed speed thresholds, because timing depends on
the machine and its current workload.

## Documentation and assumptions

The assignment leaves several details—such as cipher modes, padding, transposition-key direction,
RSA text encoding, and the meaning of listing ECC points—unspecified. The project records its explicit
decisions in [docs/requirements-analysis.md](docs/requirements-analysis.md).

Guided implementation documents remain under `docs/` as an explanation of how each component was
built. [docs/implementation-plan.md](docs/implementation-plan.md) records the original staged build
plan rather than the current implementation status.

The authoritative assignment is [CSE721 Project requirements.pdf](CSE721%20Project%20requirements.pdf).
