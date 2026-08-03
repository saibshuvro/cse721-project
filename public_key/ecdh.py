"""Elliptic-curve Diffie-Hellman using validated domain parameters."""

from __future__ import annotations

from public_key.ecc import Curve, Point


def generate_private_key(curve: Curve) -> int:
    """Generate a scalar in the validated generator subgroup."""

    raise NotImplementedError("Implement ECDH private-key generation")


def public_key(curve: Curve, private_key: int) -> Point:
    """Derive ``private_key * G`` after checking scalar bounds."""

    raise NotImplementedError("Implement ECDH public-key derivation")


def shared_point(curve: Curve, private_key: int, peer_public_key: Point) -> Point:
    """Validate the peer point and derive the shared ECDH point."""

    raise NotImplementedError("Implement ECDH shared-point derivation")

