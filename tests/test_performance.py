"""Tests for the generic performance-measurement foundation."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from analysis.performance import BenchmarkCase, benchmark, run_benchmark_case


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_collects_samples_and_calculates_statistics(self) -> None:
        call_count = 0

        def operation() -> None:
            nonlocal call_count
            call_count += 1

        # Three start/end pairs produce samples of 60, 100, and 150 ns.
        clock_values = (100, 160, 200, 300, 400, 550)
        with patch(
            "analysis.performance.perf_counter_ns",
            side_effect=clock_values,
        ):
            summary = benchmark("example operation", operation, repetitions=3)

        self.assertEqual(call_count, 3)
        self.assertEqual(summary.operation, "example operation")
        self.assertEqual(summary.repetitions, 3)
        self.assertEqual(summary.samples_ns, (60, 100, 150))
        self.assertAlmostEqual(summary.mean_ns, 310 / 3)
        self.assertEqual(summary.median_ns, 100.0)
        self.assertAlmostEqual(summary.stdev_ns, 45.09249752822894)

    def test_one_repetition_has_zero_standard_deviation(self) -> None:
        with patch(
            "analysis.performance.perf_counter_ns",
            side_effect=(1_000, 1_025),
        ):
            summary = benchmark("single sample", lambda: None, repetitions=1)

        self.assertEqual(summary.samples_ns, (25,))
        self.assertEqual(summary.mean_ns, 25.0)
        self.assertEqual(summary.median_ns, 25.0)
        self.assertEqual(summary.stdev_ns, 0.0)

    def test_invalid_operation_name_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            benchmark(123, lambda: None)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            benchmark("   ", lambda: None)

    def test_non_callable_function_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            benchmark("invalid", None)  # type: ignore[arg-type]

    def test_invalid_repetition_count_is_rejected(self) -> None:
        for repetitions in (True, 1.5, "3"):
            with self.subTest(repetitions=repetitions):
                with self.assertRaises(TypeError):
                    benchmark(
                        "invalid repetitions",
                        lambda: None,
                        repetitions=repetitions,  # type: ignore[arg-type]
                    )

        for repetitions in (0, -1):
            with self.subTest(repetitions=repetitions):
                with self.assertRaises(ValueError):
                    benchmark(
                        "invalid repetitions",
                        lambda: None,
                        repetitions=repetitions,
                    )

    def test_operation_exception_is_not_hidden(self) -> None:
        def failing_operation() -> None:
            raise RuntimeError("operation failed")

        with self.assertRaisesRegex(RuntimeError, "operation failed"):
            benchmark("failure", failing_operation, repetitions=1)


class StructuredBenchmarkTests(unittest.TestCase):
    def test_case_validates_and_formats_its_metadata(self) -> None:
        case = BenchmarkCase(
            algorithm="Example",
            operation="encrypt",
            input_size=16,
            input_unit="bytes",
            key_parameters="test key",
            repetitions=2,
            warmups=1,
            prepare=lambda: lambda: None,
        )

        self.assertEqual(
            case.label,
            "Example: encrypt (16 bytes) [test key]",
        )

        with self.assertRaises(ValueError):
            BenchmarkCase(
                algorithm="",
                operation="encrypt",
                input_size=16,
                input_unit="bytes",
                key_parameters="test key",
                repetitions=2,
                warmups=1,
                prepare=lambda: lambda: None,
            )
        with self.assertRaises(ValueError):
            BenchmarkCase(
                algorithm="Example",
                operation="encrypt",
                input_size=None,
                input_unit="bytes",
                key_parameters="test key",
                repetitions=2,
                warmups=1,
                prepare=lambda: lambda: None,
            )
        with self.assertRaises(TypeError):
            BenchmarkCase(
                algorithm="Example",
                operation="encrypt",
                input_size=16,
                input_unit="bytes",
                key_parameters="test key",
                repetitions=2,
                warmups=True,
                prepare=lambda: lambda: None,
            )

    def test_run_case_excludes_warmups_from_recorded_samples(self) -> None:
        call_count = 0

        def operation() -> None:
            nonlocal call_count
            call_count += 1

        case = BenchmarkCase(
            algorithm="Example",
            operation="operation",
            input_size=None,
            input_unit=None,
            key_parameters="parameters",
            repetitions=2,
            warmups=1,
            prepare=lambda: operation,
        )

        with patch(
            "analysis.performance.perf_counter_ns",
            side_effect=(100, 110, 200, 230),
        ):
            result = run_benchmark_case(case)

        self.assertIs(result.case, case)
        self.assertEqual(call_count, 3)
        self.assertEqual(result.timing.samples_ns, (10, 30))
        self.assertEqual(result.timing.operation, case.label)

    def test_run_case_requires_callable_prepared_operation(self) -> None:
        case = BenchmarkCase(
            algorithm="Example",
            operation="invalid preparation",
            input_size=None,
            input_unit=None,
            key_parameters="parameters",
            repetitions=1,
            warmups=0,
            prepare=lambda: None,  # type: ignore[arg-type,return-value]
        )

        with self.assertRaises(TypeError):
            run_benchmark_case(case)


if __name__ == "__main__":
    unittest.main()
