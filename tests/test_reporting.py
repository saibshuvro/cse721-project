"""Tests for environment metadata and performance-report exports."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from analysis.performance import (
    BenchmarkCase,
    BenchmarkResult,
    TimingSummary,
)
from analysis.reporting import (
    EnvironmentMetadata,
    collect_environment_metadata,
    export_performance_csv,
    export_performance_markdown,
    export_performance_reports,
)


def _metadata() -> EnvironmentMetadata:
    return EnvironmentMetadata(
        generated_at_utc="2026-08-17T12:00:00+00:00",
        python_version="3.12.0",
        python_implementation="CPython",
        operating_system="TestOS-1",
        machine="test-machine",
        processor="test-processor",
    )


def _result() -> BenchmarkResult:
    case = BenchmarkCase(
        algorithm="AES-128",
        operation="ECB encrypt",
        input_size=16,
        input_unit="bytes",
        key_parameters="key | 128 bits",
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


class EnvironmentMetadataTests(unittest.TestCase):
    def test_collected_environment_fields_are_nonempty(self) -> None:
        metadata = collect_environment_metadata()

        self.assertTrue(metadata.generated_at_utc.endswith("+00:00"))
        self.assertTrue(metadata.python_version)
        self.assertTrue(metadata.python_implementation)
        self.assertTrue(metadata.operating_system)
        self.assertTrue(metadata.machine)
        self.assertTrue(metadata.processor)

    def test_metadata_rejects_empty_fields(self) -> None:
        with self.assertRaises(ValueError):
            EnvironmentMetadata(
                generated_at_utc="",
                python_version="3.12.0",
                python_implementation="CPython",
                operating_system="TestOS-1",
                machine="test-machine",
                processor="test-processor",
            )


class PerformanceExportTests(unittest.TestCase):
    def test_csv_contains_metadata_statistics_and_raw_samples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "nested" / "performance.csv"
            returned_path = export_performance_csv(
                (_result(),),
                path,
                _metadata(),
                suite_name="quick",
            )

            self.assertEqual(returned_path, path)
            with path.open(encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["suite"], "quick")
        self.assertEqual(row["algorithm"], "AES-128")
        self.assertEqual(row["input_size"], "16")
        self.assertEqual(row["repetitions"], "2")
        self.assertEqual(float(row["mean_ms"]), 0.15)
        self.assertEqual(json.loads(row["samples_ns"]), [100_000, 200_000])
        self.assertEqual(row["operating_system"], "TestOS-1")

    def test_markdown_contains_environment_table_and_escaped_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "performance.md"
            export_performance_markdown(
                (_result(),),
                path,
                _metadata(),
                suite_name="full",
            )
            report = path.read_text(encoding="utf-8")

        self.assertIn("Cryptographic Performance Analysis — Full", report)
        self.assertIn("CPython 3.12.0", report)
        self.assertIn("TestOS-1", report)
        self.assertIn("key \\| 128 bits", report)
        self.assertIn("| 1 | 2 | 0.150000 | 0.150000 |", report)
        self.assertIn("Input/key preparation", report)
        self.assertIn("Performance alone does not determine", report)

    def test_combined_export_creates_standard_report_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "results"
            paths = export_performance_reports(
                (_result(),),
                output_directory,
                metadata=_metadata(),
                suite_name="quick",
            )

            self.assertEqual(paths.csv_path, output_directory / "performance.csv")
            self.assertEqual(
                paths.markdown_path,
                output_directory / "performance.md",
            )
            self.assertTrue(paths.csv_path.is_file())
            self.assertTrue(paths.markdown_path.is_file())

    def test_export_rejects_invalid_or_inconsistent_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "performance.csv"

            with self.assertRaises(TypeError):
                export_performance_csv([_result()], path, _metadata())  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                export_performance_csv((), path, _metadata())
            with self.assertRaises(TypeError):
                export_performance_csv((_result(),), path, "metadata")  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                export_performance_csv((_result(),), path, _metadata(), " ")

            result = _result()
            invalid_timing = TimingSummary(
                operation="wrong label",
                repetitions=2,
                samples_ns=(100, 200),
                mean_ns=150.0,
                median_ns=150.0,
                stdev_ns=70.0,
            )
            inconsistent_result = BenchmarkResult(
                case=result.case,
                timing=invalid_timing,
            )
            with self.assertRaises(ValueError):
                export_performance_csv(
                    (inconsistent_result,),
                    path,
                    _metadata(),
                )


if __name__ == "__main__":
    unittest.main()
