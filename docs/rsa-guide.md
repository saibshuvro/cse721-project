# Understanding and guided implementation of RSA

Implement textbook RSA in [`public_key/rsa.py`](../public_key/rsa.py) and the deliberately small
factorization demonstration in [`public_key/factorization.py`](../public_key/factorization.py).
Complete the TODO functions in the stages near the end of this guide.

Primary references used for the design:

- [RFC 8017: PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017)
- [NIST FIPS 186-5, especially Appendix A and Miller-Rabin in Appendix
  B.3](https://doi.org/10.6028/NIST.FIPS.186-5)
- [NIST SP 800-56B Rev. 2](https://doi.org/10.6028/NIST.SP.800-56Br2)
- [Python `secrets` documentation](https://docs.python.org/3/library/secrets.html)

## 1. Scope decision for this project

The project PDF asks for randomized RSA keys such as 512 or 1024 bits, plaintext-string
encryption, integer or hexadecimal ciphertext, decryption, and an optional factorization result.
It permits big integers and basic mathematics but forbids cryptographic libraries for core logic.

This project therefore implements:

| Feature | Coursework decision |
|---|---|
| RSA form | Ordinary two-prime RSA, `n = p*q` |
| Normal menu sizes | 512 and 1024 bits, because the PDF explicitly suggests them |
| Public exponent | Fixed `e = 65537` by default |
| Prime generation | Random odd candidates plus Miller-Rabin |
| Modular exponentiation | From-scratch square-and-multiply |
| Public key | `(n, e)` |
| Private key | `(n, d)` |
| Ciphertext | A list of integers; the CLI can also display each integer in hex |
| Text handling | UTF-8 divided into reversible modulus-bounded blocks |
| Encryption scheme | Textbook RSA for education, clearly labelled insecure |
| Factorization attack | Bounded trial division on a separate tiny toy modulus |

These choices are not a standards-compliant production RSA implementation. In current NIST
guidance, approved RSA key-establishment moduli start at 2048 bits. The assignment's 512/1024-bit
choices are useful only for demonstrating the algorithm. Real encryption also needs a randomized
encoding such as OAEP, careful side-channel resistance, key validation, and mature library code.

## 2. RSA's central idea

RSA uses two related exponents over the same modulus:

```text
Public key:  (n, e)
Private key: (n, d)
```

Anyone may know `n` and `e`. Only the owner should know `d`; the generating primes `p` and `q`
must also remain secret.

For an integer message representative `m` in the range `0 <= m < n`:

```text
Encryption: c = m^e mod n
Decryption: m = c^d mod n
```

Both operations are modular exponentiation. Their purpose differs because the keys differ. Do not
describe applying a private exponent as “encrypting with the private key.” RSA signatures use a
private-key primitive together with a signature encoding scheme such as PSS; signing is not simply
encryption in reverse.

## 3. Mathematical foundation 1: modular arithmetic

`a mod n` means the remainder after dividing `a` by `n`. Two integers are congruent modulo `n`
when they have the same remainder:

```text
a ≡ b (mod n)
```

RSA reduces every multiplication modulo `n`. This keeps values below `n`, even though an expression
such as `m^d` would otherwise contain an enormous number of digits.

For example:

```text
7^4 = 2401
2401 mod 10 = 1
therefore 7^4 ≡ 1 (mod 10)
```

## 4. Mathematical foundation 2: GCD and coprimality

The greatest common divisor `gcd(a, b)` is the largest positive integer dividing both numbers.
Euclid's algorithm repeatedly uses remainders:

```text
gcd(240, 46)
= gcd(46, 240 mod 46)
= gcd(46, 10)
= gcd(10, 6)
= gcd(6, 4)
= gcd(4, 2)
= gcd(2, 0)
= 2
```

Two numbers are **coprime** when their GCD is 1. RSA needs the public exponent to be coprime with
the totient-related value used to construct the private exponent.

## 5. Mathematical foundation 3: extended Euclid and modular inverse

The extended Euclidean algorithm returns coefficients `x` and `y` satisfying Bézout's identity:

```text
a*x + b*y = gcd(a, b)
```

If `gcd(a, b) = 1`, reduce the coefficient `x` modulo `b`:

```text
a*x ≡ 1 (mod b)
```

Then `x` is the modular inverse of `a` modulo `b`.

RSA uses this to calculate `d`:

```text
d = e^-1 mod phi(n)
```

This does not mean `1/e` in ordinary arithmetic. It means finding an integer `d` such that:

```text
e*d mod phi(n) = 1
```

An inverse exists only when `gcd(e, phi(n)) = 1`.

## 6. Mathematical foundation 4: fast modular exponentiation

Calculating `base**exponent` first is infeasible for RSA. Square-and-multiply reads the exponent's
binary bits and reduces after each operation.

Conceptual algorithm:

```text
result = 1
base = base mod modulus

while exponent > 0:
    if exponent is odd:
        result = (result * base) mod modulus
    base = (base * base) mod modulus
    exponent = exponent // 2
```

Dividing the exponent by 2 each iteration makes the number of iterations proportional to the
exponent's bit length, rather than to the exponent itself. This same helper is used by Miller-Rabin,
RSA encryption, and RSA decryption.

## 7. Exact RSA key-generation sequence

### Step 1: choose two secret random primes

Generate two distinct probable primes `p` and `q`. For an intended 512-bit modulus, each candidate
is 256 bits; for a 1024-bit modulus, each is 512 bits.

Candidate generation must:

1. use `secrets.randbits`, not the simulation-oriented `random` module;
2. set the highest bit so the candidate has the requested size;
3. set the lowest bit so the candidate is odd;
4. ensure `gcd(candidate - 1, e) = 1`; and
5. accept it only after Miller-Rabin probable-prime testing.

### Step 2: calculate the modulus

```text
n = p*q
```

The modulus appears in both keys. Multiplying two half-size primes can occasionally produce a
modulus one bit shorter than requested, so key generation retries until:

```text
n.bit_length() == requested_bits
```

### Step 3: calculate the course totient

For two distinct primes:

```text
phi(n) = (p - 1)*(q - 1)
```

RFC 8017 states RSA key validity using Carmichael's function:

```text
lambda(n) = lcm(p - 1, q - 1)
```

and requires `e*d ≡ 1 mod lambda(n)`. Introductory RSA usually derives `d` modulo `phi(n)`. That
is correct: `lambda(n)` divides `phi(n)`, so an inverse relationship modulo `phi(n)` also satisfies
the required relationship modulo `lambda(n)`. This project uses `phi(n)` because the course
proposal explicitly calls for Euler's totient.

### Step 4: choose the public exponent

Use:

```text
e = 65537
```

It must be odd, greater than 1, and coprime with the totient. Prime generation checks the necessary
GCD conditions before accepting `p` and `q`.

### Step 5: derive the private exponent

```text
d = e^-1 mod phi(n)
```

The extended Euclidean algorithm computes this inverse.

### Step 6: construct the keys

```text
Public key:  (n, e)
Private key: (n, d)
```

The program keeps `p` and `q` in `KeyPair` only for coursework inspection and tests. They are
private material. Revealing either prime allows the other to be calculated as `n // p`, after which
an attacker can reconstruct `d`.

## 8. Complete small worked example

Use tiny primes only to make the arithmetic visible:

```text
p = 61
q = 53

n = p*q = 3233
phi(n) = (61 - 1)*(53 - 1) = 60*52 = 3120
```

Choose:

```text
e = 17
gcd(17, 3120) = 1
```

Find the inverse:

```text
d = 2753
17*2753 mod 3120 = 1
```

The keys are:

```text
Public:  (n=3233, e=17)
Private: (n=3233, d=2753)
```

Encrypt integer `m = 65`:

```text
c = 65^17 mod 3233 = 2790
```

Decrypt:

```text
m = 2790^2753 mod 3233 = 65
```

The staged tests use this example to pin the arithmetic. It is not a secure key.

## 9. Why decryption restores the message

Because `d` is the inverse of `e`, there is an integer `k` such that:

```text
e*d = 1 + k*phi(n)
```

For messages coprime to `n`, Euler's theorem gives:

```text
m^phi(n) ≡ 1 (mod n)
```

Therefore:

```text
(m^e)^d
= m^(e*d)
= m^(1 + k*phi(n))
= m*(m^phi(n))^k
≡ m*1^k
≡ m (mod n)
```

RSA also works for message representatives that share a factor with `n`; that full result is shown
by considering the congruence separately modulo `p` and modulo `q`, then combining the results via
the Chinese Remainder Theorem.

## 10. Miller-Rabin probable-prime testing

Trying every divisor up to the square root is far too slow for 256- or 512-bit prime candidates.
Miller-Rabin searches for evidence that an odd candidate `n` is composite.

First decompose:

```text
n - 1 = 2^s * d
```

where `d` is odd. For a randomly selected base `a`, compute:

```text
x = a^d mod n
```

The round passes if `x` is initially `1` or `n-1`. Otherwise square repeatedly:

```text
x = x^2 mod n
```

up to `s-1` times, looking for `n-1`. If it never appears, that base is a witness proving the
candidate composite. Passing all rounds means **probably prime**, not provably prime.

FIPS 186-5 specifies how Miller-Rabin iteration counts depend on prime size, generation method,
and target error probability. This educational implementation uses 40 randomized rounds as a
simple explicit project assumption; it is not claiming FIPS validation.

## 11. RSA integer encryption and decryption boundaries

RFC 8017's basic RSA encryption primitive accepts only:

```text
0 <= m < n
```

and the decryption primitive accepts only:

```text
0 <= c < n
```

Do not silently reduce an out-of-range message with `m % n`. That would change the caller's input
and destroy reversibility. Reject it with `ValueError`.

The two core operations are exactly:

```text
encrypt_int: modular_exponentiation(message, e, n)
decrypt_int: modular_exponentiation(ciphertext, d, n)
```

## 12. Converting plaintext strings into RSA integers

RSA encrypts integers, not Python strings. The terminal wrapper must:

```text
string -> UTF-8 bytes -> bounded integer blocks -> RSA integers
```

Each integer must remain strictly below `n`. For a modulus with bit length `k`, this project permits
an encoded block of:

```text
floor((k - 1) / 8) bytes
```

This guarantees the resulting integer is below `2^(k-1)` and therefore below `n`. One byte is
reserved for a nonzero marker, leaving:

```text
maximum payload = floor((k - 1) / 8) - 1 bytes
```

For a 512-bit modulus:

```text
maximum encoded block = floor(511 / 8) = 63 bytes
maximum text payload = 62 bytes per RSA operation
```

Each block is encoded as:

```text
0x01 || payload bytes
```

Why add the marker? Converting an integer back to its shortest byte representation would otherwise
lose zero bytes at the beginning of a payload block. The leading `0x01` preserves the complete
payload and identifies a valid block. It is not randomized and is not OAEP.

The encrypted text result is a list because every plaintext block creates one ciphertext integer:

```text
[c0, c1, c2, ...]
```

Empty text maps to an empty list and back to an empty string.

## 13. Textbook RSA versus secure RSA encryption

Textbook RSA is deterministic:

```text
same message block + same public key -> same ciphertext integer
```

That leaks equality and structure. It is also algebraically malleable and provides no integrity or
authentication. RFC 8017 describes complete encryption schemes that combine RSA primitives with
an encoding method; OAEP is the required scheme for new applications in that specification.

This project does not implement OAEP because the assignment asks for the core algorithm from
scratch and suggests small 512-bit keys. For example, OAEP with SHA-256 needs a modulus long enough
for two 32-byte hash lengths plus overhead, leaving no payload at all under a 512-bit modulus.

The report and CLI must say:

> This is a deterministic textbook-RSA demonstration, not secure RSA encryption.

## 14. Factorization attack: why it recovers the private key

The public modulus is:

```text
n = p*q
```

If an attacker factors `n`, they can reconstruct:

```text
phi(n) = (p - 1)*(q - 1)
d = e^-1 mod phi(n)
```

The attack therefore follows:

```text
public (n, e)
   -> factor n into p and q
   -> calculate phi(n)
   -> calculate d
   -> recover the private key
```

Trial division tests possible factors through the square root, so its work grows roughly with
`sqrt(n)`. It is suitable only for tiny semiprimes. The project attack must use a separate 32- to
40-bit toy key or the visible `3233 = 53*61` example. It must not attempt to factor the normal
512/1024-bit demonstration key or run an unbounded loop.

The bounded function returns `None` when it does not find a divisor. That means “not found within
this educational bound,” not “the modulus is prime.”

## 15. Exact implementation order

### Stage 1: integer validation

Implement:

```python
_require_integer()
```

This helper should reject `bool`, even though Python treats booleans as integer subclasses.

### Stage 2: Euclidean arithmetic

Implement:

```python
greatest_common_divisor()
extended_gcd()
modular_inverse()
```

Verify both the GCD and Bézout identity before continuing.

### Stage 3: modular exponentiation

Implement:

```python
modular_exponentiation()
```

Confirm the worked values `65^17 mod 3233 = 2790` and
`2790^2753 mod 3233 = 65`.

### Stage 4: primality and prime generation

Implement:

```python
is_probable_prime()
generate_probable_prime()
```

Test small primes, ordinary composites, Carmichael composites, exact candidate bit length, oddness,
and the public-exponent GCD condition.

### Stage 5: key validation and key generation

Implement:

```python
_validate_public_key()
_validate_private_key()
generate_keypair()
```

Use small 64- or 128-bit keys only in automated tests so the suite remains fast. The eventual CLI
will expose the assignment's 512/1024-bit choices.

### Stage 6: raw integer RSA

Implement:

```python
encrypt_int()
decrypt_int()
```

Enforce the `0 <= value < n` range rather than silently applying modulo.

### Stage 7: reversible UTF-8 blocking

Implement:

```python
maximum_text_payload_bytes()
_encode_text_blocks()
_decode_text_blocks()
encrypt_text()
decrypt_text()
```

Test multi-block Bengali/UTF-8 text, zero bytes, empty text, malformed markers, and invalid UTF-8.

### Stage 8: bounded factorization demonstration

Implement in [`public_key/factorization.py`](../public_key/factorization.py):

```python
trial_division()
recover_private_exponent()
```

The test uses `3233`, factors `53` and `61`, and recovers `d = 2753`.

### Stage 9: terminal submenu

Only after all RSA tests pass, create `cli/rsa_menu.py`:

```text
RSA

1. Generate keys
2. Encrypt plaintext
3. Decrypt integer/hex ciphertext blocks
4. Run toy factorization demonstration
5. Return to main menu
```

The CLI should display the public key `(n,e)`, private key `(n,d)`, modulus size, ciphertext blocks
in integer and hex form, recovered plaintext, and attack timing/result. Mark main-menu option 5
implemented only after this submenu exists and is tested.

## 16. Frequent RSA mistakes to avoid

1. Generating primes with `random` instead of cryptographically strong randomness.
2. Forgetting to set the candidate's top bit and receiving undersized primes.
3. Forgetting to force candidates odd.
4. Allowing `p == q`.
5. Assuming two half-size primes always produce an exact-size modulus.
6. Choosing `e` without checking coprimality.
7. Treating a modular inverse as ordinary division.
8. Computing the enormous power before taking modulo.
9. Accepting message or ciphertext integers greater than or equal to `n`.
10. Converting a whole arbitrary string into one integer without checking it against `n`.
11. Losing leading zero bytes during integer-to-byte conversion.
12. Calling textbook RSA secure encryption or calling private-key exponentiation “encryption.”
13. Printing or exporting `p`, `q`, or `d` as though they were public values.
14. Attempting trial division on the normal 512/1024-bit demonstration key.
15. Claiming 512/1024-bit RSA meets current real-world guidance.

## 17. Running the staged tests

At first, only the RSA configuration test runs; the implementation tests are deliberately skipped.
After each stage, remove only its matching `@unittest.skip` decorator in
[`tests/test_rsa.py`](../tests/test_rsa.py).

Run the RSA tests:

```bash
python3 -m unittest tests.test_rsa -v
```

Then run the complete project suite:

```bash
python3 -m unittest discover -s tests -v
```
