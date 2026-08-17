"""Sequential runners for quick and full performance experiments.

Benchmark cases run one at a time. Parallel execution would make algorithms
compete for CPU time and would therefore make the comparison less reliable.
This module performs no terminal output; a CLI may receive progress through an
optional callback without adding printing time to any measured sample.
"""

from __future__ import annotations

from typing import Callable, TypeAlias

from analysis.benchmark_cases import build_benchmark_cases
from analysis.performance import BenchmarkCase, BenchmarkResult, run_benchmark_case


QUICK_MESSAGE_SIZES = (16, 256)
QUICK_RSA_MESSAGE_SIZES = (16, 64)
QUICK_RSA_KEY_SIZES = (512, 1024)
QUICK_REDUCED_ALPHABET_SIZES = (3, 5)
QUICK_REPETITIONS = 5
QUICK_SLOW_REPETITIONS = 1

SuiteProgressCallback: TypeAlias = Callable[[int, int, BenchmarkCase], None]


def run_benchmark_suite(
    cases: tuple[BenchmarkCase, ...],
    progress_callback: SuiteProgressCallback | None = None,
) -> tuple[BenchmarkResult, ...]:
    """Run selected cases sequentially and preserve their supplied order.

    ``progress_callback`` is called immediately before each case using a
    one-based index, total case count, and the case metadata. The callback is
    outside every timed region, so a terminal menu can safely display messages
    such as ``Running 3/40`` without changing the operation measurements.
    """

    if type(cases) is not tuple:
        raise TypeError("Benchmark cases must be a tuple")
    if not cases:
        raise ValueError("Benchmark suite must contain at least one case")

    for index, case in enumerate(cases):
        if not isinstance(case, BenchmarkCase):
            raise TypeError(f"Benchmark case {index} must be a BenchmarkCase")

    labels = tuple(case.label for case in cases)
    if len(set(labels)) != len(labels):
        raise ValueError("Benchmark suite must not contain duplicate case labels")

    if progress_callback is not None and not callable(progress_callback):
        raise TypeError("Progress callback must be callable or None")

    results: list[BenchmarkResult] = []
    total_cases = len(cases)

    for case_number, case in enumerate(cases, start=1):
        if progress_callback is not None:
            progress_callback(case_number, total_cases, case)
        results.append(run_benchmark_case(case))

    return tuple(results)


def run_quick_benchmark_suite(
    progress_callback: SuiteProgressCallback | None = None,
) -> tuple[BenchmarkResult, ...]:
    """Run a presentation-friendly sample that still covers every component.

    Two message sizes retain visible size comparisons, both coursework RSA key
    sizes retain the key-size comparison, and lower repetition counts keep the
    run suitable for an interactive demonstration.
    """

    cases = build_benchmark_cases(
        message_sizes=QUICK_MESSAGE_SIZES,
        rsa_message_sizes=QUICK_RSA_MESSAGE_SIZES,
        rsa_key_sizes=QUICK_RSA_KEY_SIZES,
        reduced_alphabet_sizes=QUICK_REDUCED_ALPHABET_SIZES,
        repetitions=QUICK_REPETITIONS,
        slow_repetitions=QUICK_SLOW_REPETITIONS,
    )
    return run_benchmark_suite(cases, progress_callback=progress_callback)


def run_full_benchmark_suite(
    progress_callback: SuiteProgressCallback | None = None,
) -> tuple[BenchmarkResult, ...]:
    """Run the complete report-quality experiment defined by default cases."""

    cases = build_benchmark_cases()
    return run_benchmark_suite(cases, progress_callback=progress_callback)
