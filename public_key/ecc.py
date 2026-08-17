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

    ``bool`` needs an explicit check because it is a subclass of ``int`` in
    Python, but ``True`` and ``False`` are not meaningful ECC coordinates or
    scalars in this interface.
    """

    # Python treats bool as a subclass of int, but True and False are not
    # meaningful coordinate or scalar inputs for this ECC interface.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")

    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")

    return value


def is_prime(candidate: int) -> bool:
    """Return whether a small integer is prime using trial division.

    This simple test is appropriate for the tiny coursework field. Production
    curve parameters are standardized and validated with stronger processes.
    """

    if isinstance(candidate, bool) or not isinstance(candidate, int):
        return False
    if candidate < 2:
        return False
    if candidate == 2:
        return True
    if candidate % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= candidate:
        if candidate % divisor == 0:
            return False
        divisor += 2

    return True


def modular_inverse(value: int, modulus: int) -> int:
    """Return ``value^-1 mod modulus`` using the extended Euclidean algorithm.

    In the point-addition formulas, a fraction means multiplication by a
    modular inverse. Ordinary floating-point division must never be used.
    """

    validated_value = _require_integer(value, "Value")
    validated_modulus = _require_integer(modulus, "Modulus", minimum=2)
    reduced_value = validated_value % validated_modulus

    # Track the coefficient of reduced_value while Euclid reduces the pair
    # (modulus, reduced_value) to their greatest common divisor.
    old_remainder, current_remainder = validated_modulus, reduced_value
    old_coefficient, current_coefficient = 0, 1

    while current_remainder != 0:
        quotient = old_remainder // current_remainder
        old_remainder, current_remainder = (
            current_remainder,
            old_remainder - quotient * current_remainder,
        )
        old_coefficient, current_coefficient = (
            current_coefficient,
            old_coefficient - quotient * current_coefficient,
        )

    if old_remainder != 1:
        raise ValueError(
            f"{validated_value} has no inverse modulo {validated_modulus}"
        )

    return old_coefficient % validated_modulus


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

        prime = _require_integer(self.prime, "Field prime", minimum=5)
        coefficient_a = _require_integer(self.a, "Curve coefficient a")
        coefficient_b = _require_integer(self.b, "Curve coefficient b")

        if not is_prime(prime):
            raise ValueError("Field modulus must be prime")

        if not 0 <= coefficient_a < prime:
            raise ValueError("Curve coefficient a must be in the interval 0..p-1")
        if not 0 <= coefficient_b < prime:
            raise ValueError("Curve coefficient b must be in the interval 0..p-1")

        discriminant_term = (
            4 * coefficient_a * coefficient_a * coefficient_a
            + 27 * coefficient_b * coefficient_b
        ) % prime
        if discriminant_term == 0:
            raise ValueError("Curve is singular because its discriminant is zero")

        generator_parameter = self.generator
        order_parameter = self.order
        if (generator_parameter is None) != (order_parameter is None):
            raise ValueError("Generator G and subgroup order n must be supplied together")

        # Point-only arithmetic is valid without selecting a generator
        # subgroup. ECDH's helper applies the stronger requirement later.
        if generator_parameter is None and order_parameter is None:
            return

        # The paired-presence check above makes this branch unreachable, but
        # spelling it out gives static type checkers exact non-None types.
        if generator_parameter is None or order_parameter is None:
            raise ValueError("Generator G and subgroup order n must be supplied together")

        generator = self._require_point(
            generator_parameter,
            "Generator G",
            allow_infinity=False,
        )
        order = _require_integer(order_parameter, "Subgroup order n", minimum=2)

        if not is_prime(order):
            raise ValueError("Subgroup order n must be prime")
        if self.multiply(order, generator) is not None:
            raise ValueError("Subgroup order n is inconsistent with generator G")

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

        if point is INFINITY:
            return True
        if not isinstance(point, Point):
            return False

        if (
            isinstance(point.x, bool)
            or not isinstance(point.x, int)
            or isinstance(point.y, bool)
            or not isinstance(point.y, int)
        ):
            return False

        if not (0 <= point.x < self.prime and 0 <= point.y < self.prime):
            return False

        left_side = (point.y * point.y) % self.prime
        right_side = (
            point.x * point.x * point.x + self.a * point.x + self.b
        ) % self.prime
        return left_side == right_side

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

        if point is INFINITY:
            if allow_infinity:
                return INFINITY
            raise ValueError(f"{name} must not be the point at infinity")

        if not isinstance(point, Point):
            raise TypeError(f"{name} must be a Point or the point at infinity")

        if not self.contains(point):
            raise ValueError(f"{name} is not a valid point on this curve")

        return point

    def negate(self, point: PointLike) -> PointLike:
        """Return the additive inverse ``-(x, y) = (x, -y mod p)``.

        TODO(student): validate the point, leave infinity unchanged, and return
        ``Point(point.x, (-point.y) % self.prime)`` for an affine point.
        """

        validated_point = self._require_point(point, "Point")
        if validated_point is None:
            return INFINITY

        return Point(
            x=validated_point.x,
            y=(-validated_point.y) % self.prime,
        )

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

        left_point = self._require_point(left, "Left point")
        right_point = self._require_point(right, "Right point")

        # The point at infinity is the additive identity.
        if left_point is None:
            return right_point
        if right_point is None:
            return left_point

        prime = self.prime

        # Points with the same x-coordinate and opposite y-coordinates are
        # additive inverses. This also handles doubling when y == 0, where the
        # tangent is vertical and 2P is infinity.
        if (
            left_point.x == right_point.x
            and (left_point.y + right_point.y) % prime == 0
        ):
            return INFINITY

        if left_point == right_point:
            numerator = 3 * left_point.x * left_point.x + self.a
            denominator = 2 * left_point.y
        else:
            numerator = right_point.y - left_point.y
            denominator = right_point.x - left_point.x

        slope = (
            numerator * modular_inverse(denominator, prime)
        ) % prime
        result_x = (
            slope * slope - left_point.x - right_point.x
        ) % prime
        result_y = (
            slope * (left_point.x - result_x) - left_point.y
        ) % prime
        result = Point(result_x, result_y)

        if not self.contains(result):
            raise ArithmeticError("Point addition produced an off-curve result")

        return result

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

        remaining_scalar = _require_integer(scalar, "Scalar")
        validated_point = self._require_point(point, "Point")

        if remaining_scalar == 0 or validated_point is None:
            return INFINITY

        addend: PointLike = validated_point
        if remaining_scalar < 0:
            remaining_scalar = -remaining_scalar
            addend = self.negate(addend)

        result: PointLike = INFINITY

        while remaining_scalar > 0:
            if remaining_scalar & 1:
                result = self.add(result, addend)

            addend = self.add(addend, addend)
            remaining_scalar >>= 1

        return result

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

        self.validate()

        if self.prime > MAX_ENUMERATION_PRIME:
            raise ValueError(
                "Field prime is too large for exhaustive point enumeration; "
                f"maximum supported p is {MAX_ENUMERATION_PRIME}"
            )

        points: list[PointLike] = [INFINITY]

        for x_coordinate in range(self.prime):
            for y_coordinate in range(self.prime):
                point = Point(x_coordinate, y_coordinate)
                if self.contains(point):
                    points.append(point)

        return tuple(points)

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

        self.validate()
        validated_point = self._require_point(point, "Point")

        if validated_point is None:
            return 1

        group_size = len(self.enumerate_points())
        accumulated: PointLike = INFINITY

        for order in range(1, group_size + 1):
            accumulated = self.add(accumulated, validated_point)
            if accumulated is None:
                return order

        raise ValueError(
            "Point order was not found within the enumerated curve group"
        )


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
