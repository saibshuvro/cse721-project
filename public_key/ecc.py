"""Elliptic-curve arithmetic over a small prime field."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True)
class Point:
    x: int
    y: int


PointLike: TypeAlias = Point | None
INFINITY: PointLike = None


@dataclass(frozen=True)
class Curve:
    prime: int
    a: int
    b: int
    generator: Point | None = None
    order: int | None = None

    def validate(self) -> None:
        """Reject non-prime fields, singular curves, or inconsistent domain parameters."""

        raise NotImplementedError("Implement elliptic-curve validation")

    def contains(self, point: PointLike) -> bool:
        """Return whether a point is on this curve; infinity is always a member."""

        raise NotImplementedError("Implement point-membership testing")

    def add(self, left: PointLike, right: PointLike) -> PointLike:
        """Add or double two points, including identity and inverse cases."""

        raise NotImplementedError("Implement elliptic-curve point addition")

    def multiply(self, scalar: int, point: PointLike) -> PointLike:
        """Use double-and-add scalar multiplication."""

        raise NotImplementedError("Implement elliptic-curve scalar multiplication")

    def enumerate_points(self) -> tuple[PointLike, ...]:
        """Enumerate the small educational curve, including infinity."""

        raise NotImplementedError("Implement small-curve point enumeration")

