"""Timing harness that keeps setup/key generation separate from measured operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class TimingSummary:
    operation: str
    repetitions: int
    samples_ns: tuple[int, ...]
    mean_ns: float
    median_ns: float
    stdev_ns: float


def benchmark(operation: str, function: Callable[[], T], repetitions: int = 30) -> TimingSummary:
    """Measure a no-argument operation repeatedly with ``perf_counter_ns``."""

    raise NotImplementedError("Implement repeatable timing and summary statistics")

