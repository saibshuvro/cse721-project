# Understanding and guided implementation of ECC and ECDH

Implement finite-field elliptic-curve arithmetic in
[`public_key/ecc.py`](../public_key/ecc.py), then build ECDH in
[`public_key/ecdh.py`](../public_key/ecdh.py). Complete the TODO functions in the staged order near
the end of this guide.

Primary references used for the design:

- [RFC 6090: Fundamental Elliptic Curve Cryptography Algorithms](https://www.rfc-editor.org/rfc/rfc6090)
- [NIST SP 800-186: Elliptic Curve Domain Parameters](https://doi.org/10.6028/NIST.SP.800-186)
- [NIST SP 800-56A Revision 3: Pair-Wise Key Establishment](https://doi.org/10.6028/NIST.SP.800-56Ar3)
- [Python `secrets` documentation](https://docs.python.org/3/library/secrets.html)

## 1. What the assignment is asking for

The PDF's ECC section asks for:

```text
Domain parameters: (p, a, b, G, n)
Primitive element: P(x, y)
Outputs:
    list of all Ps
    private key
    public key
ECDH inputs: a, b
ECDH output: shared key
```

Some of that wording is ambiguous. This project uses these precise interpretations:

| Requirement wording | Project interpretation |
|---|---|
| `(p, a, b, G, n)` | Prime-field short-Weierstrass curve, generator point, and generator order |
| “Primitive element `P(x,y)`” | An affine curve point; `G` is the distinguished generator/base point |
| “List of all Ps” | Infinity plus every affine point on a tiny educational curve |
| Private key | Integer scalar `d` in `1..n-1` |
| Public key | Point `Q = dG` |
| ECDH inputs `a, b` | Alice's and Bob's private scalars, named `alice_private` and `bob_private` |
| Shared key | Matching shared point, plus its raw x-coordinate for display |

Calling the participants' secrets `a` and `b` would clash with the curve coefficients. Use `dA`
and `dB`, or `alice_private` and `bob_private`, instead.

The assignment does **not** ask for elliptic-curve message encryption. ECC is a family of
techniques, not one encryption algorithm. The required public/private-key demonstration and ECDH
key agreement satisfy this section; do not invent an unauthenticated “ECC encrypt/decrypt” scheme.

## 2. Scope decision for this project

Use this educational domain:

```text
p = 17
a = 2
b = 2
G = (5, 1)
n = 19

Curve: y^2 = x^3 + 2x + 2 (mod 17)
```

It has 18 affine points plus the point at infinity, for a group size of 19. Since 19 is prime,
every affine point has order 19; the selected `G=(5,1)` generates the entire group. The cofactor is:

```text
h = #E(F_p) / n = 19 / 19 = 1
```

This choice makes every assignment output visible and testable. It provides no security: an
attacker can try all 18 possible private keys immediately. Real curves have enormous fields, and
enumerating their points is infeasible.

## 3. ECC is arithmetic over a finite field

The familiar drawings of elliptic curves use real numbers and show a smooth curve. Cryptographic
ECC instead uses a finite field. For this project:

```text
F_17 = {0, 1, 2, ..., 16}
```

Every coordinate and intermediate value is reduced modulo 17. The resulting “curve” is a finite
set of coordinate pairs rather than a continuous line.

The basic operations are:

```text
addition:       (x + y) mod p
subtraction:    (x - y) mod p
multiplication: (x * y) mod p
division:       x * inverse(y) mod p
```

There is no floating-point division. A fraction such as `(y2-y1)/(x2-x1)` means multiplying by the
modular inverse of its denominator.

For example, the inverse of 2 modulo 17 is 9:

```text
2 * 9 = 18 = 1 (mod 17)
```

## 4. The curve equation and point membership

For a prime `p > 3`, the short-Weierstrass form is:

```text
y^2 = x^3 + a*x + b (mod p)
```

An affine `Point(x, y)` belongs to the curve only when both sides have the same remainder modulo
`p`. For `G=(5,1)` on the default curve:

```text
left  = 1^2 mod 17
      = 1

right = (5^3 + 2*5 + 2) mod 17
      = 137 mod 17
      = 1
```

Therefore `(5,1)` is on the curve. `(1,1)` is not:

```text
left  = 1
right = (1 + 2 + 2) mod 17 = 5
```

Coordinates received through the API must already be in the canonical interval `0..p-1`.
Mathematically, `(22,1)` reduces to `(5,1)`, but silently accepting it is undesirable for public-key
validation. `contains(Point(22,1))` therefore returns `False`.

## 5. The non-singular-curve requirement

The coefficients must satisfy:

```text
4*a^3 + 27*b^2 != 0 (mod p)
```

This is the nonzero-discriminant condition. If it fails, the graph has a cusp or self-intersection,
and the point set does not have the elliptic-curve group structure required by ECC.

For the default curve:

```text
4*2^3 + 27*2^2 = 32 + 108 = 140
140 mod 17 = 4
```

The result is nonzero, so the curve is non-singular.

## 6. The point at infinity

ECC needs one special point with no ordinary `(x,y)` coordinates: the **point at infinity**, often
written `O`, `∞`, or `Ø`. It is the additive identity:

```text
O + P = P
P + O = P
```

This project represents it with the unique sentinel:

```python
INFINITY = None
```

It is a member of every curve group, but it is never a valid ECDH public key or shared result.

## 7. Negation and inverse points

The inverse of an affine point reflects its y-coordinate modulo `p`:

```text
-(x, y) = (x, -y mod p)
```

For the generator:

```text
-G = -(5,1) = (5,16)
```

Adding inverse points gives infinity:

```text
G + (-G) = O
```

This explains why most affine points in the enumeration occur in pairs with the same x-coordinate:
`(x,y)` and `(x,p-y)`.

## 8. Point addition: all required branches

The method `Curve.add(P, Q)` has several cases. Their order matters because the general slope
formula has a zero denominator in the exceptional cases.

### Case 1: an identity input

```text
O + Q = Q
P + O = P
```

Return the other point without trying to calculate a slope.

### Case 2: inverse points or a vertical tangent

When `x1 == x2` and `(y1+y2) mod p == 0`:

```text
P + Q = O
```

This covers distinct inverse points. It also covers doubling a point with `y=0`, because that point
is its own inverse and `2*y mod p == 0`.

### Case 3: doubling one point

When `P == Q` and `y1 != 0`, calculate:

```text
slope = (3*x1^2 + a) * inverse(2*y1) mod p
```

Then use the common output formulas:

```text
x3 = slope^2 - x1 - x2 mod p
y3 = slope*(x1-x3) - y1 mod p
```

Worked example for `2G`, where `G=(5,1)`:

```text
inverse(2*1) mod 17 = inverse(2) = 9
slope = (3*5^2 + 2) * 9 mod 17
      = 77 * 9 mod 17
      = 13

x3 = 13^2 - 5 - 5 mod 17
   = 6

y3 = 13*(5-6) - 1 mod 17
   = 3

2G = (6,3)
```

### Case 4: two distinct, non-inverse points

Calculate:

```text
slope = (y2-y1) * inverse(x2-x1) mod p
```

Then use the same `x3` and `y3` formulas. For `G + 2G`:

```text
P = (5,1)
Q = (6,3)
slope = (3-1) * inverse(6-5) mod 17 = 2
x3 = 2^2 - 5 - 6 mod 17 = 10
y3 = 2*(5-10) - 1 mod 17 = 6

3G = (10,6)
```

After constructing a result, defensively check that it still satisfies the curve equation. If it
does not, there is a bug in the arithmetic or the parameters.

## 9. Scalar multiplication

ECC writes repeated addition as scalar multiplication:

```text
kP = P + P + ... + P        (k copies)
```

Public keys and ECDH depend on this operation. Repeating `add` exactly `k` times would be too slow,
so use binary **double-and-add**, analogous to square-and-multiply in RSA:

```text
result = O
addend = P

while k > 0:
    if k is odd:
        result = result + addend
    addend = addend + addend
    k = k // 2
```

Each loop consumes one binary bit of `k`, making the operation require `O(log k)` additions.

Useful identities for testing are:

```text
0P = O
1P = P
(-k)P = -(kP)
nG = O
(n+1)G = G
```

The educational sequence for `G=(5,1)` is:

| k | kG | k | kG |
|---:|---|---:|---|
| 0 | infinity | 10 | `(7,11)` |
| 1 | `(5,1)` | 11 | `(13,10)` |
| 2 | `(6,3)` | 12 | `(0,11)` |
| 3 | `(10,6)` | 13 | `(16,4)` |
| 4 | `(3,1)` | 14 | `(9,1)` |
| 5 | `(9,16)` | 15 | `(3,16)` |
| 6 | `(16,13)` | 16 | `(10,11)` |
| 7 | `(0,6)` | 17 | `(6,14)` |
| 8 | `(13,7)` | 18 | `(5,16)` |
| 9 | `(7,6)` | 19 | infinity |

## 10. Enumerating “all Ps”

For each `x` and `y` in `0..16`, test the curve equation. Include infinity once. With loops ordered
by x and then y, the default result is:

```text
infinity
(0,6)   (0,11)
(3,1)   (3,16)
(5,1)   (5,16)
(6,3)   (6,14)
(7,6)   (7,11)
(9,1)   (9,16)
(10,6)  (10,11)
(13,7)  (13,10)
(16,4)  (16,13)
```

That is 19 group elements in total.

The straightforward algorithm tests `p^2` coordinate pairs. It is intentionally limited by
`MAX_ENUMERATION_PRIME`. A P-256-style field has roughly `2^256` x-values, so listing all points on
a production curve is not merely slow; it is physically infeasible.

## 11. Point order, subgroup order, and cofactor

The order of a point `P` is the smallest positive integer `k` satisfying:

```text
kP = O
```

The domain parameter `n` is the order of `G`. NIST domain parameters also include the cofactor:

```text
#E(F_p) = h*n
```

where `#E(F_p)` is the number of all curve points. Our PDF omits `h`, and the default curve has
`h=1`, so no extra field is required in the coursework `Curve` class.

For a small curve, calculate point order through repeated addition, bounded by the enumerated group
size. Do not confuse this explanatory routine with scalar multiplication: scalar multiplication
must use double-and-add.

## 12. Domain-parameter validation

The `Curve.validate()` method must check:

1. `p` is a prime greater than 3;
2. `a` and `b` are canonical field elements;
3. the discriminant is nonzero;
4. `G` and `n` are either both present or both absent;
5. `G` is an affine point on the curve;
6. `n` is prime and at least 2; and
7. `nG = O`.

Because this template requires prime `n`, a non-infinity `G` whose `n` multiple is infinity has
exactly order `n`: its order divides prime `n`, and it cannot be 1.

The default parameter values are verified educational parameters, not a generated or standardized
production domain. Do not let the CLI imply that arbitrary user-supplied coefficients are secure.

## 13. ECC key generation

Given valid `(p,a,b,G,n)` parameters, choose the private scalar uniformly:

```text
d in {1, 2, ..., n-1}
```

Then calculate the public point:

```text
Q = dG
```

Use `secrets.randbelow(n-1) + 1`, not `random.randint`. The latter is designed for simulation, not
secret generation.

For this tiny curve, a possible key pair is:

```text
d = 5
Q = 5G = (9,16)
```

The private key is the integer `d`. The public key is a point, not just one arbitrary coordinate.

## 14. ECDH step by step

Alice and Bob agree publicly on the same domain parameters.

### Alice

```text
private: dA = 5
public:  QA = dA*G = 5G = (9,16)
```

### Bob

```text
private: dB = 7
public:  QB = dB*G = 7G = (0,6)
```

They exchange only `QA` and `QB`.

### Alice's computation

```text
SA = dA*QB
   = 5*(7G)
   = 35G
```

### Bob's computation

```text
SB = dB*QA
   = 7*(5G)
   = 35G
```

Because `G` has order 19:

```text
35G = (35 mod 19)G = 16G = (10,11)
```

Both sides therefore derive:

```text
shared point = (10,11)
raw shared x-coordinate = 10
```

The matching point demonstrates ECDH. Do not print a sentence claiming that `(10,11)` itself is a
ready-to-use AES key.

## 15. Public-key validation before ECDH

A received public value must pass all of these checks before multiplication by a private scalar:

1. it is not infinity;
2. both coordinates are integers in `0..p-1`;
3. it satisfies the correct curve equation; and
4. `nQ = O`, proving membership in the generator subgroup.

The subgroup test seems redundant on the default curve because its cofactor is 1. It is still part
of the correct algorithm and matters on curves with more than one subgroup. The staged tests include
the small curve:

```text
y^2 = x^3 + 1 (mod 5)
G = (0,1), n = 3
```

Point `(4,0)` is on that curve but has order 2, so it must be rejected as an ECDH public key for
the order-3 generator subgroup.

This validation also prevents invalid-curve attacks. The affine addition formulas visibly contain
`a` but not `b`; without checking the original curve equation, a malicious off-curve point could be
processed under unintended group arithmetic.

## 16. Raw ECDH output versus a cryptographic key

RFC 6090 permits the shared point's x-coordinate as compact ECDH output. NIST's ECC CDH primitive
also outputs an encoding of the x-coordinate after the required point computation. A complete
key-agreement scheme then applies a defined key-derivation method with contextual information.

This project stops at:

```text
shared_point(...):    Point(x, y)
shared_secret_x(...): x
```

That matches the minimal assignment demonstration. It deliberately does not add an improvised KDF.
If the project later combines ECDH with AES, define an appropriate encoding and KDF as a separate,
explicit extension.

## 17. Security limits you should state in the report

- The default 19-element group is breakable by inspection and exists only so all points can be shown.
- The code uses affine coordinates and variable-time branches; secret-dependent timing is visible.
- Python big-integer and object operations are not designed for side-channel resistance.
- Plain ECDH does not authenticate either party and is vulnerable to a man-in-the-middle attack.
- A raw shared point or x-coordinate is not automatically an application key.
- Production systems should use standardized curves, validated mature libraries, defined encodings,
  a specified KDF, authentication, and protocol-level key confirmation where required.

NIST SP 800-186 specifies recommended production domain parameters. The small domain in this project
is intentionally not one of them.

## 18. Guided implementation order

The function order in the source file is good for reading, but not quite the dependency order for
implementation. In particular, `Curve.validate()` checks `nG`, so it depends on point membership,
addition, and scalar multiplication. Follow this sequence.

### Stage 1: integer, prime, and inverse helpers

In `public_key/ecc.py`, implement:

```python
_require_integer()
is_prime()
modular_inverse()
```

Remove the skip named `Student TODO: implement ECC integer, prime, and inverse helpers`, then run:

```bash
python3 -m unittest tests.test_ecc.ECCFoundationTests -v
```

### Stage 2: point membership and strict point validation

Implement:

```python
Curve.contains()
Curve._require_point()
```

Remember that infinity is a curve member, but `_require_point` can reject it when
`allow_infinity=False`.

Run:

```bash
python3 -m unittest tests.test_ecc.ECCMembershipTests -v
```

### Stage 3: negation and point addition

Implement:

```python
Curve.negate()
Curve.add()
```

Handle identity and inverse branches before either slope formula. Remove only the first skip in
`ECCGroupLawTests`, then run:

```bash
python3 -m unittest tests.test_ecc.ECCGroupLawTests -v
```

One scalar-multiplication test will remain skipped at this point.

### Stage 4: scalar multiplication

Implement:

```python
Curve.multiply()
```

Remove the matching skip and rerun `ECCGroupLawTests`.

### Stage 5: complete domain validation

Now implement:

```python
Curve.validate()
```

It is now safe for validation to calculate `nG`. Run:

```bash
python3 -m unittest tests.test_ecc.ECCCurveValidationTests -v
```

### Stage 6: enumerate all points

Implement:

```python
Curve.enumerate_points()
```

Remove its skip and run:

```bash
python3 -m unittest tests.test_ecc.ECCEnumerationTests -v
```

The point-order test remains skipped until Stage 7.

### Stage 7: calculate point order

Implement:

```python
Curve.point_order()
```

Remove its skip and rerun `ECCEnumerationTests`.

### Stage 8: ECDH domain and private-key helpers

In `public_key/ecdh.py`, implement:

```python
_validated_generator_parameters()
_validate_private_key()
generate_private_key()
```

Then run:

```bash
python3 -m unittest tests.test_ecc.ECDHTests -v
```

Only the private-key test should be enabled at this stage.

### Stage 9: public-key derivation

Implement:

```python
public_key()
```

Remove its matching skip and rerun `ECDHTests`.

### Stage 10: peer validation and shared-secret derivation

Implement:

```python
_validate_peer_public_key()
shared_point()
shared_secret_x()
```

Remove the last two ECDH skips and run the complete ECC file:

```bash
python3 -m unittest tests.test_ecc -v
```

Finally, run the whole project suite:

```bash
python3 -m unittest discover -s tests -v
```

## 19. What the later ECC menu should show

After all core tests pass, create `cli/ecc_menu.py` and connect main-menu option 6. A suitable menu
is:

```text
ECC / ECDH

1. Show and validate domain parameters
2. List all curve points
3. Inspect a point and its order
4. Generate an ECC key pair
5. Demonstrate Alice/Bob ECDH
6. Return to main menu
```

For an ECDH demonstration, display:

```text
Curve equation and (p,a,b,G,n)
Alice private/public values
Bob private/public values
Alice's shared point
Bob's shared point
Matching raw x-coordinate
Educational-security warning
```

Keep menu input/output out of `ecc.py` and `ecdh.py`. That separation lets the arithmetic tests run
without simulating terminal input.
