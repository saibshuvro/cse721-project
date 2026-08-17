"""Timing harness that keeps setup/key generation separate from measured operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import fmean, median, stdev
from time import perf_counter_ns
from typing import Callable, TypeAlias, TypeVar


T = TypeVar("T")
PreparedOperation: TypeAlias = Callable[[], object]
OperationPreparation: TypeAlias = Callable[[], PreparedOperation]


@dataclass(frozen=True)
class TimingSummary:
    operation: str
    repetitions: int
    samples_ns: tuple[int, ...]
    mean_ns: float
    median_ns: float
    stdev_ns: float


@dataclass(frozen=True)
class BenchmarkCase:
    """One fully described operation that can be prepared and measured.

    ``prepare`` is deliberately separate from the timed operation. It may
    generate a fixed key, encrypt a message needed by a decryption test, or do
    other setup. It must then return a no-argument callable containing only
    the operation represented by this case.
    """

    algorithm: str
    operation: str
    input_size: int | None
    input_unit: str | None
    key_parameters: str
    repetitions: int
    warmups: int
    prepare: OperationPreparation = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for value, name in (
            (self.algorithm, "Algorithm name"),
            (self.operation, "Operation name"),
            (self.key_parameters, "Key/parameter description"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value.strip():
                raise ValueError(f"{name} must not be empty")

        if self.input_size is None:
            if self.input_unit is not None:
                raise ValueError("Input unit must be None when input size is None")
        else:
            if isinstance(self.input_size, bool) or not isinstance(
                self.input_size,
                int,
            ):
                raise TypeError("Input size must be an integer or None")
            if self.input_size < 0:
                raise ValueError("Input size must not be negative")
            if not isinstance(self.input_unit, str):
                raise TypeError("Input unit must be a string when input size is set")
            if not self.input_unit.strip():
                raise ValueError("Input unit must not be empty")

        if isinstance(self.repetitions, bool) or not isinstance(
            self.repetitions,
            int,
        ):
            raise TypeError("Repetitions must be an integer")
        if self.repetitions < 1:
            raise ValueError("Repetitions must be at least 1")

        if isinstance(self.warmups, bool) or not isinstance(self.warmups, int):
            raise TypeError("Warmups must be an integer")
        if self.warmups < 0:
            raise ValueError("Warmups must not be negative")

        if not callable(self.prepare):
            raise TypeError("Case preparation must be callable")

    @property
    def label(self) -> str:
        """Return a unique human-readable label for timing output."""

        label = f"{self.algorithm}: {self.operation}"
        if self.input_size is not None:
            label += f" ({self.input_size} {self.input_unit})"
        return f"{label} [{self.key_parameters}]"


@dataclass(frozen=True)
class BenchmarkResult:
    """Keep a case's metadata beside the timing summary it produced."""

    case: BenchmarkCase
    timing: TimingSummary


def benchmark(
    operation: str,
    function: Callable[[], T],
    repetitions: int = 30,
) -> TimingSummary:
    """Measure a no-argument operation repeatedly with ``perf_counter_ns``.

    ``function`` should contain only the operation being compared. For
    example, an encryption benchmark should prepare its plaintext and key
    before calling this function instead of generating a key inside the timed
    callable.

    The function's return values are intentionally ignored. If the function
    raises an exception, that exception is allowed to propagate because a
    failed cryptographic operation must not be reported as a valid timing.
    """

    if not isinstance(operation, str):
        raise TypeError("Operation name must be a string")
    if not operation.strip():
        raise ValueError("Operation name must not be empty")

    if not callable(function):
        raise TypeError("Benchmarked function must be callable")

    # bool is a subclass of int in Python, so it needs an explicit rejection.
    if isinstance(repetitions, bool) or not isinstance(repetitions, int):
        raise TypeError("Repetitions must be an integer")
    if repetitions < 1:
        raise ValueError("Repetitions must be at least 1")

    samples: list[int] = []

    for _ in range(repetitions):
        start_ns = perf_counter_ns()
        function()
        end_ns = perf_counter_ns()
        samples.append(end_ns - start_ns)

    samples_ns = tuple(samples)

    # Sample standard deviation requires at least two observations. A
    # one-repetition benchmark has no measured variation, so report 0.0.
    standard_deviation = stdev(samples_ns) if repetitions > 1 else 0.0

    return TimingSummary(
        operation=operation,
        repetitions=repetitions,
        samples_ns=samples_ns,
        mean_ns=fmean(samples_ns),
        median_ns=float(median(samples_ns)),
        stdev_ns=standard_deviation,
    )


def run_benchmark_case(case: BenchmarkCase) -> BenchmarkResult:
    """Prepare, warm up, and measure one structured benchmark case."""

    if not isinstance(case, BenchmarkCase):
        raise TypeError("case must be a BenchmarkCase")

    timed_operation = case.prepare()
    if not callable(timed_operation):
        raise TypeError("Case preparation must return a callable operation")

    # Warm-up calls are intentionally not recorded. They reduce one-time
    # interpreter/cache effects without changing the requested sample count.
    for _ in range(case.warmups):
        timed_operation()

    timing = benchmark(
        case.label,
        timed_operation,
        repetitions=case.repetitions,
    )
    return BenchmarkResult(case=case, timing=timing)
