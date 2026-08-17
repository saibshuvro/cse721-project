"""Interactive menu for comparative performance and security analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from analysis.benchmark_suite import (
    run_full_benchmark_suite,
    run_quick_benchmark_suite,
)
from analysis.performance import BenchmarkCase, BenchmarkResult
from analysis.reporting import (
    DEFAULT_RESULTS_DIRECTORY,
    export_performance_reports,
)
from analysis.security_analysis import (
    export_security_markdown,
    render_terminal_security_comparison,
)


def _input_description(case: BenchmarkCase) -> str:
    """Return a compact description of a case's measured input."""

    if case.input_size is None:
        return "N/A"
    return f"{case.input_size} {case.input_unit}"


def _display_progress(index: int, total: int, case: BenchmarkCase) -> None:
    """Show progress outside the operation's measured time."""

    print(
        f"[{index:>2}/{total}] {case.algorithm} — {case.operation} — "
        f"{_input_description(case)}"
    )


def _display_performance_results(
    results: tuple[BenchmarkResult, ...],
    suite_name: str,
) -> None:
    """Display a compact summary while detailed parameters remain in exports."""

    if type(results) is not tuple or not results:
        raise ValueError("No benchmark results are available")

    print(f"\nPerformance results — {suite_name.title()} suite")
    print(
        f"{'Algorithm':<21} {'Operation':<27} {'Input':<27} "
        f"{'Reps':>5} {'Mean ms':>11} {'Median ms':>11} {'Std ms':>11}"
    )
    print("-" * 119)

    for result in results:
        case = result.case
        timing = result.timing
        print(
            f"{case.algorithm:<21} "
            f"{case.operation:<27} "
            f"{_input_description(case):<27} "
            f"{timing.repetitions:>5} "
            f"{timing.mean_ns / 1_000_000:>11.6f} "
            f"{timing.median_ns / 1_000_000:>11.6f} "
            f"{timing.stdev_ns / 1_000_000:>11.6f}"
        )

    sample_count = sum(len(result.timing.samples_ns) for result in results)
    print(f"\nCases measured: {len(results)}")
    print(f"Recorded timing samples: {sample_count}")
    print("Use the median as the primary comparison statistic.")
    print("Performance is not a measure of cryptographic security.")


def _run_suite(suite_name: str) -> tuple[BenchmarkResult, ...]:
    """Run one named suite with progress and display its results."""

    if suite_name == "quick":
        print("\nRunning the quick benchmark suite...")
        results = run_quick_benchmark_suite(_display_progress)
    elif suite_name == "full":
        print("\nRunning the full report-quality benchmark suite.")
        print("This uses more input sizes and repetitions and may take longer.")
        results = run_full_benchmark_suite(_display_progress)
    else:
        raise ValueError("Suite name must be 'quick' or 'full'")

    _display_performance_results(results, suite_name)
    return results


def _export_reports(
    results: tuple[BenchmarkResult, ...] | None,
    suite_name: str | None,
    output_directory: Path = DEFAULT_RESULTS_DIRECTORY,
) -> None:
    """Export the latest performance results and the security comparison."""

    if results is None or suite_name is None:
        raise ValueError("Run the quick or full benchmark suite before exporting")

    performance_paths = export_performance_reports(
        results,
        output_directory=output_directory,
        suite_name=suite_name,
    )
    security_path = export_security_markdown(
        output_directory / "security_analysis.md"
    )

    print("\nReports exported successfully:")
    print(f"Performance CSV: {performance_paths.csv_path.resolve()}")
    print(f"Performance Markdown: {performance_paths.markdown_path.resolve()}")
    print(f"Security Markdown: {security_path.resolve()}")


def run_analysis_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run analysis operations until returning to the main menu."""

    latest_results: tuple[BenchmarkResult, ...] | None = None
    latest_suite_name: str | None = None

    while True:
        print("\nComparative Performance and Security Analysis")
        print("1. Run quick performance benchmarks")
        print("2. Run full performance benchmarks")
        print("3. Show latest performance results")
        print("4. Show security comparison")
        print("5. Export performance and security reports")
        print("6. Return to main menu")

        choice = input_fn("Select an operation: ").strip()

        try:
            if choice == "1":
                latest_results = _run_suite("quick")
                latest_suite_name = "quick"
            elif choice == "2":
                latest_results = _run_suite("full")
                latest_suite_name = "full"
            elif choice == "3":
                if latest_results is None or latest_suite_name is None:
                    raise ValueError("Run a benchmark suite before displaying results")
                _display_performance_results(latest_results, latest_suite_name)
            elif choice == "4":
                print()
                print(render_terminal_security_comparison())
            elif choice == "5":
                _export_reports(latest_results, latest_suite_name)
            elif choice == "6":
                return
            else:
                print("\nInvalid selection. Enter a number from 1 to 6.")
        except (TypeError, ValueError, OSError) as error:
            print(f"\nError: {error}")
