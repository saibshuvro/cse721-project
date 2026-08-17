"""Guided elliptic-curve arithmetic over a small prime field.

Coursework scope
----------------
This module models a short-Weierstrass curve over the prime field F_p:

    y^2 = x^3 + a*x + b  (mod p)

It will implement domain-parameter validation, point membership, negation,
point addition/doubling, scalar multiplication, point-order calculation, and
enumeration of every point on a deliberately tiny educational curve.

``None`` represents the point at infinity. This is convenient for a small
terminal project, but it means every method must handle that identity element
explicitly.

The default curve has only 19 points and is completely insecure. Enumeration
and affine-coordinate formulas are useful for learning; they are unsuitable
for real cryptographic systems. Complete the TODO functions in the order
described in ``docs/ecc-guide.md``. Core functions must not call ``input`` or
``print``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


# Point enumeration checks every (x, y) pair, so its work is proportional to
# p^2. This explicit guard prevents an accidental attempt to enumerate a real
# cryptographic-size curve.
MAX_ENUMERATION_PRIME = 1_000


def _require_integer(
    value: int,
    name: str,
    minimum: int | None = None,
) -> int:
    """Validate an exact integer, optionally enforcing an inclusive minimum.

    TODO(student):
        1. Reject non-integers and booleans with ``TypeError``.
        2. If ``minimum`` is not ``None``, reject values below it.
        3. Return the validated integer.

    ``bool`` needs an explicit check because it is a subclass of ``int`` in
    Python, but ``True`` and ``False`` are not meaningful ECC coordinates or
    scalars in this interface.
    """

    raise NotImplementedError("TODO(student): validate an ECC integer")


def is_prime(candidate: int) -> bool:
    """Return whether a small integer is prime using trial division.

    TODO(student):
        1. Return False for non-integers, booleans, and values below 2.
        2. Handle 2 directly, then reject other even values.
        3. Try odd divisors beginning at 3.
        4. Continue only while ``divisor * divisor <= candidate``.
        5. Return False on exact division and True if no divisor is found.

    This simple test is appropriate for the tiny coursework field. Production
    curve parameters are standardized and validated with stronger processes.
    """

    raise NotImplementedError("TODO(student): test a small field modulus")


def modular_inverse(value: int, modulus: int) -> int:
    """Return ``value^-1 mod modulus`` using the extended Euclidean algorithm.

    TODO(student):
        1. Require an integer value and a modulus of at least 2.
        2. Reduce value modulo modulus.
        3. Run iterative extended Euclid while tracking the coefficient of
           value for each remainder.
        4. If the final GCD is not 1, raise ``ValueError``.
        5. Return the coefficient reduced modulo ``modulus``.

    In the point-addition formulas, a fraction means multiplication by a
    modular inverse. Ordinary floating-point division must never be used.
    """

    raise NotImplementedError("TODO(student): implement a modular inverse")


@dataclass(frozen=True)
class Point:
    """One affine elliptic-curve point with integer coordinates."""

    x: int
    y: int


# The point at infinity has no finite x/y coordinates. ``None`` is its unique
# sentinel in this project, so PointLike means either an affine point or the
# group identity.
PointLike: TypeAlias = Point | None
INFINITY: PointLike = None


@dataclass(frozen=True)
class Curve:
    """Short-Weierstrass curve and optional generator-subgroup parameters.

    The assignment names the domain parameters ``(p, a, b, G, n)``:

    * ``prime`` is p, the modulus of the finite field;
    * ``a`` and ``b`` are curve coefficients;
    * ``generator`` is G, the base point; and
    * ``order`` is n, the additive order of G.

    A curve may omit both G and n when only point arithmetic is needed. ECDH
    requires both of them.
    """

    prime: int
    a: int
    b: int
    generator: PointLike = INFINITY
    order: int | None = None

    def validate(self) -> None:
        """Reject an invalid field, singular curve, or inconsistent G and n.

        TODO(student):
            1. Require p, a, and b to be exact integers.
            2. Require a prime p greater than 3.
            3. Require canonical coefficients ``0 <= a,b < p``.
            4. Reject a singular curve when
               ``(4*a**3 + 27*b**2) % p == 0``.
            5. Require G and n to be either both supplied or both omitted.
            6. When supplied, require:
                 * G is an affine point on this curve;
                 * n is a prime integer of at least 2; and
                 * ``n * G`` is the point at infinity.

        Because n is prime and G is not infinity, ``n*G = INFINITY`` proves
        that G has order n. Do not enumerate every point during validation;
        enumeration is a separate, deliberately small-curve operation.
        """

        raise NotImplementedError("TODO(student): validate ECC domain parameters")

    def contains(self, point: PointLike) -> bool:
        """Return whether ``point`` is represented on this curve.

        TODO(student):
            1. Return True for ``INFINITY`` because it is the group identity.
            2. Return False unless the value is a ``Point`` with exact integer
               (non-boolean) coordinates.
            3. Require canonical coordinates ``0 <= x,y < p``. Do not silently
               reduce a received public key modulo p.
            4. Compare ``y**2 % p`` with
               ``(x**3 + a*x + b) % p``.

        This method answers a question and therefore returns False rather than
        raising for an invalid affine point.
        """

        raise NotImplementedError("TODO(student): test point membership")

    def _require_point(
        self,
        point: PointLike,
        name: str,
        *,
        allow_infinity: bool = True,
    ) -> PointLike:
        """Validate one point for internal arithmetic operations.

        TODO(student): distinguish these cases:

        * infinity is accepted only when ``allow_infinity`` is True;
        * a non-``Point`` value raises ``TypeError``; and
        * an affine point that is not on this curve raises ``ValueError``.

        The leading underscore marks this as an internal helper. Users should
        normally call ``contains`` or the public arithmetic methods.
        """

        raise NotImplementedError("TODO(student): require a valid curve point")

    def negate(self, point: PointLike) -> PointLike:
        """Return the additive inverse ``-(x, y) = (x, -y mod p)``.

        TODO(student): validate the point, leave infinity unchanged, and return
        ``Point(point.x, (-point.y) % self.prime)`` for an affine point.
        """

        raise NotImplementedError("TODO(student): negate an elliptic-curve point")

    def add(self, left: PointLike, right: PointLike) -> PointLike:
        """Return ``left + right`` using affine-coordinate group formulas.

        TODO(student): validate both inputs, then handle the branches in this
        order:

        1. Identity:
             ``INFINITY + Q = Q`` and ``P + INFINITY = P``.
        2. Vertical/inverse case:
             if x1 == x2 and ``(y1 + y2) % p == 0``, return INFINITY.
             This also handles doubling a point whose y-coordinate is zero.
        3. Doubling P == Q:
             slope = (3*x1**2 + a) * inverse(2*y1) mod p
        4. Distinct points:
             slope = (y2-y1) * inverse(x2-x1) mod p
        5. Calculate:
             x3 = slope**2 - x1 - x2 mod p
             y3 = slope*(x1-x3) - y1 mod p
        6. Construct the result and defensively verify that it is on the curve.

        Every subtraction and multiplication is finite-field arithmetic, so
        reduce the final coordinate expressions modulo p.
        """

        raise NotImplementedError("TODO(student): add elliptic-curve points")

    def multiply(self, scalar: int, point: PointLike) -> PointLike:
        """Return ``scalar * point`` with the binary double-and-add algorithm.

        TODO(student):
            1. Require an exact integer scalar and a valid point.
            2. Return INFINITY for scalar 0 or an infinity input.
            3. For a negative scalar, negate the point and use ``-scalar``.
            4. Set ``result = INFINITY`` and ``addend = point``.
            5. While scalar is positive:
                 * if its lowest bit is 1, add addend into result;
                 * double addend; and
                 * shift scalar right by one bit.
            6. Return result.

        This requires O(log scalar) group operations rather than adding the
        point ``scalar`` times.
        """

        raise NotImplementedError("TODO(student): multiply an elliptic-curve point")

    def enumerate_points(self) -> tuple[PointLike, ...]:
        """List infinity and every affine point on a small curve.

        TODO(student):
            1. Validate the curve.
            2. Reject p above ``MAX_ENUMERATION_PRIME`` with ``ValueError``.
            3. Begin a list with ``INFINITY``.
            4. For every x and y in ``range(p)``, append ``Point(x, y)`` when
               it satisfies the curve equation.
            5. Return the points as a tuple.

        The simple nested loops intentionally reveal what “all points” means.
        They cost p^2 membership checks and must not be used for real curves.
        """

        raise NotImplementedError("TODO(student): enumerate the educational curve")

    def point_order(self, point: PointLike) -> int:
        """Return the smallest positive k for which ``k * point`` is infinity.

        TODO(student):
            1. Validate the curve and point.
            2. Return 1 for infinity.
            3. Use ``len(self.enumerate_points())`` as a safe small-curve bound.
            4. Repeatedly add the point to an accumulator, beginning at
               infinity, and return the first count that reaches infinity.
            5. Raise ``ValueError`` if the bound is exhausted; that would
               indicate an implementation or parameter inconsistency.

        This repeated-addition routine is intentionally explanatory, not an
        efficient order-finding algorithm.
        """

        raise NotImplementedError("TODO(student): calculate a small point order")


# This entire group has 19 points (18 affine points plus infinity). Since 19
# is prime, every affine point is a generator; (5, 1) is a conventional choice.
# These values are small enough to enumerate by hand and far too small for any
# real security.
DEFAULT_CURVE = Curve(
    prime=17,
    a=2,
    b=2,
    generator=Point(5, 1),
    order=19,
)
