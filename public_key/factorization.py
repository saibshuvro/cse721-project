"""Guided factorization attack for deliberately tiny RSA moduli only.

Normal 512/1024-bit coursework keys must never be sent to this trial-division
routine. The CLI attack demonstration will generate a separate toy modulus.
"""

from __future__ import annotations

from public_key.rsa import modular_inverse


DEFAULT_MAX_TRIAL_DIVISOR = 1_000_000


def trial_division(
    modulus: int,
    max_divisor: int = DEFAULT_MAX_TRIAL_DIVISOR,
) -> tuple[int, int] | None:
    """Return non-trivial factors found within a deliberate work bound.

    TODO(student):
        1. Validate that modulus is an integer greater than 3.
        2. Validate that max_divisor is an integer at least 2.
        3. Return ``(2, modulus // 2)`` immediately for an even modulus.
        4. Try odd divisors starting at 3 while both conditions hold:
             divisor * divisor <= modulus
             divisor <= max_divisor
        5. On exact division, return the two factors in ascending order.
        6. Return ``None`` if the bound is reached without finding a factor.

    ``None`` does not prove that the modulus is prime; it may merely mean the
    configured educational search bound was too small.
    """

    if isinstance(modulus, bool) or not isinstance(modulus, int):
        raise TypeError("Modulus must be an integer")
    if modulus <= 3:
        raise ValueError("Modulus must be greater than 3")

    if isinstance(max_divisor, bool) or not isinstance(max_divisor, int):
        raise TypeError("Maximum divisor must be an integer")
    if max_divisor < 2:
        raise ValueError("Maximum divisor must be at least 2")

    if modulus % 2 == 0:
        return 2, modulus // 2

    divisor = 3
    while divisor * divisor <= modulus and divisor <= max_divisor:
        if modulus % divisor == 0:
            other_factor = modulus // divisor
            # divisor cannot exceed the paired factor while it is at or below
            # sqrt(modulus), but sort explicitly to preserve the API promise.
            if divisor <= other_factor:
                return divisor, other_factor
            return other_factor, divisor

        divisor += 2

    return None


def recover_private_exponent(
    modulus: int,
    public_exponent: int,
    max_divisor: int = DEFAULT_MAX_TRIAL_DIVISOR,
) -> int:
    """Factor a toy modulus and reconstruct its RSA private exponent.

    TODO(student):
        1. Call ``trial_division`` with the explicit bound.
        2. Raise ``ValueError`` when no factors are found.
        3. Let the factors be p and q and compute phi = (p-1)*(q-1).
        4. Return ``modular_inverse(public_exponent, phi)`` from ``rsa.py``.

    This demonstrates the RSA security dependency: once p and q are recovered,
    the attacker can derive the same private exponent construction as the key
    owner. It is not intended as a competitive factorization algorithm.
    """

    if isinstance(public_exponent, bool) or not isinstance(public_exponent, int):
        raise TypeError("Public exponent must be an integer")
    if public_exponent < 3 or public_exponent % 2 == 0:
        raise ValueError("Public exponent must be an odd integer of at least 3")

    factors = trial_division(modulus, max_divisor=max_divisor)
    if factors is None:
        raise ValueError("No factors were found within the trial-division bound")

    prime_p, prime_q = factors
    totient = (prime_p - 1) * (prime_q - 1)

    return modular_inverse(public_exponent, totient)
