"""Guided elliptic-curve Diffie-Hellman over validated domain parameters.

This module builds ECDH from the point operations in ``public_key.ecc``. It
returns the educational shared point and can expose that point's x-coordinate.
A production key-agreement protocol would encode the raw secret and pass it,
together with protocol context, through an approved key-derivation method.

The tiny default curve and these variable-time Python operations are for
coursework only. They provide no real confidentiality or side-channel safety.
"""

from __future__ import annotations

import secrets

from public_key.ecc import INFINITY, Curve, Point, PointLike


def _validated_generator_parameters(curve: Curve) -> tuple[Point, int]:
    """Return a validated affine generator G and its subgroup order n.

    TODO(student):
        1. Raise ``TypeError`` unless ``curve`` is a ``Curve``.
        2. Call ``curve.validate()``.
        3. Raise ``ValueError`` if G or n was omitted.
        4. After those runtime checks, return ``(curve.generator, curve.order)``.

    Keeping this check in one helper prevents key functions from accidentally
    operating on a curve that has no generator subgroup.
    """

    if not isinstance(curve, Curve):
        raise TypeError("Curve must be a Curve")

    curve.validate()
    generator = curve.generator
    order = curve.order

    if generator is None or order is None:
        raise ValueError("ECDH requires both generator G and subgroup order n")

    return generator, order


def _validate_private_key(curve: Curve, private_key: int) -> int:
    """Require an ECDH scalar in the inclusive interval ``1..n-1``.

    TODO(student): obtain n from ``_validated_generator_parameters``, reject
    non-integers and booleans with ``TypeError``, reject values outside the
    interval with ``ValueError``, and return the validated scalar.
    """

    _, order = _validated_generator_parameters(curve)

    if isinstance(private_key, bool) or not isinstance(private_key, int):
        raise TypeError("Private key must be an integer")
    if not 1 <= private_key < order:
        raise ValueError(f"Private key must be in the interval 1..{order - 1}")

    return private_key


def _validate_peer_public_key(curve: Curve, point: PointLike) -> Point:
    """Perform full public-point validation for the educational subgroup.

    TODO(student):
        1. Obtain validated G and n parameters.
        2. Reject INFINITY; a valid public key is never the identity.
        3. Require an actual ``Point`` with canonical coordinates on the curve.
           ``curve._require_point(..., allow_infinity=False)`` may be reused.
        4. Compute ``n * point`` and require the result to be INFINITY. This
           verifies membership in G's subgroup.
        5. Return the now-validated affine point.

    The curve-equation check matters even though the addition formula does not
    visibly use coefficient b; accepting off-curve points enables invalid-curve
    attacks in real ECDH systems.
    """

    _, order = _validated_generator_parameters(curve)

    if point is None:
        raise ValueError("Peer public key must not be the point at infinity")
    if not isinstance(point, Point):
        raise TypeError("Peer public key must be a Point")
    if not curve.contains(point):
        raise ValueError("Peer public key is not a valid point on this curve")
    if curve.multiply(order, point) is not None:
        raise ValueError("Peer public key is not in the generator subgroup")

    return point


def generate_private_key(curve: Curve) -> int:
    """Generate a private scalar uniformly in the interval ``1..n-1``.

    TODO(student): validate the generator parameters and return
    ``secrets.randbelow(n - 1) + 1``. Do not use the simulation-oriented
    ``random`` module for key generation.
    """

    _, order = _validated_generator_parameters(curve)
    return secrets.randbelow(order - 1) + 1


def public_key(curve: Curve, private_key: int) -> Point:
    """Derive the public point ``Q = private_key * G``.

    TODO(student): validate the domain parameters and private scalar, multiply
    G by the scalar, defensively reject INFINITY, and return the affine point.
    """

    validated_private_key = _validate_private_key(curve, private_key)
    generator, _ = _validated_generator_parameters(curve)
    derived_point = curve.multiply(validated_private_key, generator)

    if derived_point is None:
        raise ValueError("A valid ECDH private key produced the point at infinity")

    return derived_point


def shared_point(
    curve: Curve,
    private_key: int,
    peer_public_key: PointLike,
) -> Point:
    """Derive and return ``private_key * peer_public_key``.

    TODO(student):
        1. Validate the private scalar.
        2. Fully validate the peer public point.
        3. Multiply the peer point by the private scalar.
        4. Reject INFINITY and return the affine shared point.

    If Alice has dA and Bob has dB, both sides obtain the same point because:

        dA * (dB * G) = (dA*dB) * G = dB * (dA * G)
    """

    validated_private_key = _validate_private_key(curve, private_key)
    validated_peer_key = _validate_peer_public_key(curve, peer_public_key)
    derived_point = curve.multiply(validated_private_key, validated_peer_key)

    if derived_point is None:
        raise ValueError("ECDH produced the point at infinity")

    return derived_point


def shared_secret_x(
    curve: Curve,
    private_key: int,
    peer_public_key: PointLike,
) -> int:
    """Return the x-coordinate of the validated ECDH shared point.

    TODO(student): call ``shared_point`` and return its ``x`` attribute.

    This raw integer is sufficient for the assignment's visible demonstration.
    It is not yet an AES key; real protocols use a defined encoding and KDF.
    """

    return shared_point(curve, private_key, peer_public_key).x
