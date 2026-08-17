"""Tests for sequential quick and full benchmark-suite runners."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from analysis.benchmark_suite import (
    QUICK_MESSAGE_SIZES,
    QUICK_REDUCED_ALPHABET_SIZES,
    QUICK_REPETITIONS,
    QUICK_RSA_KEY_SIZES,
    QUICK_RSA_MESSAGE_SIZES,
    QUICK_SLOW_REPETITIONS,
    run_benchmark_suite,
    run_full_benchmark_suite,
    run_quick_benchmark_suite,
)
from analysis.performance import BenchmarkCase


def _make_case(name: str, calls: list[str]) -> BenchmarkCase:
    def operation() -> None:
        calls.append(name)

    return BenchmarkCase(
        algorithm="Example",
        operation=name,
        input_size=None,
        input_unit=None,
        key_parameters=f"{name} parameters",
        repetitions=1,
        warmups=0,
        prepare=lambda: operation,
    )


class BenchmarkSuiteTests(unittest.TestCase):
    def test_selected_cases_run_in_order_and_report_progress(self) -> None:
        calls: list[str] = []
        progress: list[tuple[int, int, str]] = []
        cases = (
            _make_case("first", calls),
            _make_case("second", calls),
        )

        def record_progress(index: int, total: int, case: BenchmarkCase) -> None:
            progress.append((index, total, case.operation))

        with patch(
            "analysis.performance.perf_counter_ns",
            side_effect=(100, 110, 200, 230),
        ):
            results = run_benchmark_suite(cases, record_progress)

        self.assertEqual(calls, ["first", "second"])
        self.assertEqual(
            progress,
            [(1, 2, "first"), (2, 2, "second")],
        )
        self.assertEqual(tuple(result.case for result in results), cases)
        self.assertEqual(
            tuple(result.timing.samples_ns for result in results),
            ((10,), (30,)),
        )

    def test_suite_rejects_invalid_or_duplicate_cases(self) -> None:
        calls: list[str] = []
        case = _make_case("only", calls)

        with self.assertRaises(TypeError):
            run_benchmark_suite([case])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            run_benchmark_suite(())
        with self.assertRaises(TypeError):
            run_benchmark_suite((case, "invalid"))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            run_benchmark_suite((case, case))
        with self.assertRaises(TypeError):
            run_benchmark_suite((case,), progress_callback="invalid")  # type: ignore[arg-type]

    @patch("analysis.benchmark_suite.run_benchmark_suite")
    @patch("analysis.benchmark_suite.build_benchmark_cases")
    def test_quick_runner_uses_documented_reduced_preset(
        self,
        mock_build,
        mock_run,
    ) -> None:
        calls: list[str] = []
        cases = (_make_case("quick", calls),)
        expected_results = (object(),)
        progress_callback = lambda _index, _total, _case: None
        mock_build.return_value = cases
        mock_run.return_value = expected_results

        results = run_quick_benchmark_suite(progress_callback)

        mock_build.assert_called_once_with(
            message_sizes=QUICK_MESSAGE_SIZES,
            rsa_message_sizes=QUICK_RSA_MESSAGE_SIZES,
            rsa_key_sizes=QUICK_RSA_KEY_SIZES,
            reduced_alphabet_sizes=QUICK_REDUCED_ALPHABET_SIZES,
            repetitions=QUICK_REPETITIONS,
            slow_repetitions=QUICK_SLOW_REPETITIONS,
        )
        mock_run.assert_called_once_with(
            cases,
            progress_callback=progress_callback,
        )
        self.assertIs(results, expected_results)

    @patch("analysis.benchmark_suite.run_benchmark_suite")
    @patch("analysis.benchmark_suite.build_benchmark_cases")
    def test_full_runner_uses_complete_default_cases(
        self,
        mock_build,
        mock_run,
    ) -> None:
        calls: list[str] = []
        cases = (_make_case("full", calls),)
        expected_results = (object(),)
        mock_build.return_value = cases
        mock_run.return_value = expected_results

        results = run_full_benchmark_suite()

        mock_build.assert_called_once_with()
        mock_run.assert_called_once_with(cases, progress_callback=None)
        self.assertIs(results, expected_results)


if __name__ == "__main__":
    unittest.main()
