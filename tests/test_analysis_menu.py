"""Scripted tests for option 7 performance/security integration."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Iterable
from unittest.mock import patch

import main
from analysis.performance import BenchmarkCase, BenchmarkResult, TimingSummary
from analysis.reporting import ExportedReportPaths
from cli.analysis_menu import run_analysis_menu


def scripted_input(responses: Iterable[str]):
    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


def example_result() -> BenchmarkResult:
    case = BenchmarkCase(
        algorithm="AES-128",
        operation="ECB encrypt",
        input_size=16,
        input_unit="bytes",
        key_parameters="128-bit key",
        repetitions=2,
        warmups=1,
        prepare=lambda: lambda: None,
    )
    timing = TimingSummary(
        operation=case.label,
        repetitions=2,
        samples_ns=(100_000, 200_000),
        mean_ns=150_000.0,
        median_ns=150_000.0,
        stdev_ns=70_710.67811865476,
    )
    return BenchmarkResult(case=case, timing=timing)


class AnalysisMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_analysis_menu(scripted_input(responses))
        return output.getvalue()

    def test_quick_suite_shows_progress_results_and_latest_redisplay(self) -> None:
        result = example_result()

        def run_quick(progress_callback):
            progress_callback(1, 1, result.case)
            return (result,)

        with patch(
            "cli.analysis_menu.run_quick_benchmark_suite",
            side_effect=run_quick,
        ) as mock_quick:
            output = self.run_menu(("1", "3", "6"))

        mock_quick.assert_called_once()
        self.assertIn("[ 1/1] AES-128 — ECB encrypt — 16 bytes", output)
        self.assertEqual(output.count("Performance results — Quick suite"), 2)
        self.assertIn("0.150000", output)
        self.assertIn("Recorded timing samples: 2", output)
        self.assertIn("Performance is not a measure", output)

    def test_full_suite_uses_full_runner(self) -> None:
        result = example_result()
        with patch(
            "cli.analysis_menu.run_full_benchmark_suite",
            return_value=(result,),
        ) as mock_full:
            output = self.run_menu(("2", "6"))

        mock_full.assert_called_once()
        self.assertIn("full report-quality benchmark suite", output)
        self.assertIn("Performance results — Full suite", output)

    def test_security_comparison_is_displayed(self) -> None:
        with patch(
            "cli.analysis_menu.render_terminal_security_comparison",
            return_value="STRUCTURED SECURITY COMPARISON",
        ) as mock_render:
            output = self.run_menu(("4", "6"))

        mock_render.assert_called_once_with()
        self.assertIn("STRUCTURED SECURITY COMPARISON", output)

    def test_export_writes_performance_and_security_reports(self) -> None:
        result = example_result()
        results = (result,)
        performance_paths = ExportedReportPaths(
            csv_path=Path("results/performance.csv"),
            markdown_path=Path("results/performance.md"),
        )
        security_path = Path("results/security_analysis.md")

        with (
            patch(
                "cli.analysis_menu.run_quick_benchmark_suite",
                return_value=results,
            ),
            patch(
                "cli.analysis_menu.export_performance_reports",
                return_value=performance_paths,
            ) as mock_performance_export,
            patch(
                "cli.analysis_menu.export_security_markdown",
                return_value=security_path,
            ) as mock_security_export,
        ):
            output = self.run_menu(("1", "5", "6"))

        mock_performance_export.assert_called_once_with(
            results,
            output_directory=Path("results"),
            suite_name="quick",
        )
        mock_security_export.assert_called_once_with(
            Path("results/security_analysis.md")
        )
        self.assertIn("Reports exported successfully", output)
        self.assertIn("performance.csv", output)
        self.assertIn("security_analysis.md", output)

    def test_missing_results_and_invalid_selection_return_to_menu(self) -> None:
        output = self.run_menu(("3", "5", "9", "6"))

        self.assertIn("Error: Run a benchmark suite before displaying results", output)
        self.assertIn("Error: Run the quick or full benchmark suite before exporting", output)
        self.assertIn("Invalid selection. Enter a number from 1 to 6.", output)

    def test_main_menu_dispatches_option_seven(self) -> None:
        with patch("main.run_analysis_menu") as mock_analysis_menu:
            output = io.StringIO()
            with redirect_stdout(output):
                result = main.interactive_menu(scripted_input(("7", "8")))

        self.assertEqual(result, 0)
        mock_analysis_menu.assert_called_once()

    def test_main_component_marks_analysis_implemented(self) -> None:
        component = next(item for item in main.COMPONENTS if item.number == "7")
        self.assertTrue(component.implemented)
        self.assertIn("Security", component.name)


if __name__ == "__main__":
    unittest.main()
