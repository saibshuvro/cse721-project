"""Environment capture and CSV/Markdown performance-report exporters."""

from __future__ import annotations

import csv
import json
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
from pathlib import Path

from analysis.performance import BenchmarkResult


NANOSECONDS_PER_MILLISECOND = 1_000_000
DEFAULT_RESULTS_DIRECTORY = Path("results")


@dataclass(frozen=True)
class EnvironmentMetadata:
    """Stable execution-environment details recorded beside measurements."""

    generated_at_utc: str
    python_version: str
    python_implementation: str
    operating_system: str
    machine: str
    processor: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.generated_at_utc, "UTC generation time"),
            (self.python_version, "Python version"),
            (self.python_implementation, "Python implementation"),
            (self.operating_system, "Operating system"),
            (self.machine, "Machine architecture"),
            (self.processor, "Processor"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value.strip():
                raise ValueError(f"{name} must not be empty")


@dataclass(frozen=True)
class ExportedReportPaths:
    """Paths produced by :func:`export_performance_reports`."""

    csv_path: Path
    markdown_path: Path


def collect_environment_metadata() -> EnvironmentMetadata:
    """Capture reproducibility information without collecting personal data."""

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return EnvironmentMetadata(
        generated_at_utc=generated_at,
        python_version=platform.python_version(),
        python_implementation=platform.python_implementation(),
        operating_system=platform.platform() or "unknown",
        machine=platform.machine() or "unknown",
        processor=platform.processor() or "unknown",
    )


def _validate_suite_name(suite_name: str) -> str:
    if not isinstance(suite_name, str):
        raise TypeError("Suite name must be a string")
    normalized_name = suite_name.strip()
    if not normalized_name:
        raise ValueError("Suite name must not be empty")
    return normalized_name


def _validate_results(
    results: tuple[BenchmarkResult, ...],
) -> tuple[BenchmarkResult, ...]:
    """Reject incomplete or internally inconsistent benchmark evidence."""

    if type(results) is not tuple:
        raise TypeError("Benchmark results must be a tuple")
    if not results:
        raise ValueError("At least one benchmark result is required")

    labels: list[str] = []
    for index, result in enumerate(results):
        if not isinstance(result, BenchmarkResult):
            raise TypeError(f"Benchmark result {index} must be a BenchmarkResult")

        case = result.case
        timing = result.timing
        labels.append(case.label)

        if timing.operation != case.label:
            raise ValueError(f"Benchmark result {index} has a mismatched operation label")
        if timing.repetitions != case.repetitions:
            raise ValueError(f"Benchmark result {index} has a mismatched repetition count")
        if len(timing.samples_ns) != timing.repetitions:
            raise ValueError(f"Benchmark result {index} has an incomplete sample set")
        if any(sample < 0 for sample in timing.samples_ns):
            raise ValueError(f"Benchmark result {index} contains a negative sample")

        statistics = (timing.mean_ns, timing.median_ns, timing.stdev_ns)
        if any(not isfinite(value) or value < 0 for value in statistics):
            raise ValueError(f"Benchmark result {index} contains invalid statistics")

    if len(set(labels)) != len(labels):
        raise ValueError("Benchmark results must not contain duplicate case labels")

    return results


def _validate_metadata(metadata: EnvironmentMetadata) -> EnvironmentMetadata:
    if not isinstance(metadata, EnvironmentMetadata):
        raise TypeError("metadata must be EnvironmentMetadata")
    return metadata


def _output_path(value: str | Path, name: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise TypeError(f"{name} must be a string or Path")
    path = Path(value)
    if not path.name:
        raise ValueError(f"{name} must identify a file or directory")
    return path


def _milliseconds(nanoseconds: float) -> float:
    return nanoseconds / NANOSECONDS_PER_MILLISECOND


def export_performance_csv(
    results: tuple[BenchmarkResult, ...],
    output_path: str | Path,
    metadata: EnvironmentMetadata,
    suite_name: str = "custom",
) -> Path:
    """Write one machine-readable summary row per benchmark case."""

    results = _validate_results(results)
    path = _output_path(output_path, "CSV output path")
    metadata = _validate_metadata(metadata)
    suite_name = _validate_suite_name(suite_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = (
        "suite",
        "generated_at_utc",
        "python_version",
        "python_implementation",
        "operating_system",
        "machine",
        "processor",
        "algorithm",
        "operation",
        "input_size",
        "input_unit",
        "key_parameters",
        "warmups",
        "repetitions",
        "mean_ns",
        "median_ns",
        "stdev_ns",
        "mean_ms",
        "median_ms",
        "stdev_ms",
        "samples_ns",
    )

    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            case = result.case
            timing = result.timing
            writer.writerow(
                {
                    "suite": suite_name,
                    "generated_at_utc": metadata.generated_at_utc,
                    "python_version": metadata.python_version,
                    "python_implementation": metadata.python_implementation,
                    "operating_system": metadata.operating_system,
                    "machine": metadata.machine,
                    "processor": metadata.processor,
                    "algorithm": case.algorithm,
                    "operation": case.operation,
                    "input_size": "" if case.input_size is None else case.input_size,
                    "input_unit": "" if case.input_unit is None else case.input_unit,
                    "key_parameters": case.key_parameters,
                    "warmups": case.warmups,
                    "repetitions": timing.repetitions,
                    "mean_ns": timing.mean_ns,
                    "median_ns": timing.median_ns,
                    "stdev_ns": timing.stdev_ns,
                    "mean_ms": _milliseconds(timing.mean_ns),
                    "median_ms": _milliseconds(timing.median_ns),
                    "stdev_ms": _milliseconds(timing.stdev_ns),
                    "samples_ns": json.dumps(timing.samples_ns),
                }
            )

    return path


def _markdown_text(value: object) -> str:
    """Escape data that will occupy one Markdown table cell."""

    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def export_performance_markdown(
    results: tuple[BenchmarkResult, ...],
    output_path: str | Path,
    metadata: EnvironmentMetadata,
    suite_name: str = "custom",
) -> Path:
    """Write a presentation-ready performance table and methodology notes."""

    results = _validate_results(results)
    path = _output_path(output_path, "Markdown output path")
    metadata = _validate_metadata(metadata)
    suite_name = _validate_suite_name(suite_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# Cryptographic Performance Analysis — {_markdown_text(suite_name.title())}",
        "",
        "## Environment",
        "",
        f"- Generated at (UTC): `{_markdown_text(metadata.generated_at_utc)}`",
        (
            "- Python: "
            f"`{_markdown_text(metadata.python_implementation)} "
            f"{_markdown_text(metadata.python_version)}`"
        ),
        f"- Operating system: `{_markdown_text(metadata.operating_system)}`",
        f"- Machine architecture: `{_markdown_text(metadata.machine)}`",
        f"- Processor: `{_markdown_text(metadata.processor)}`",
        "",
        "## Results",
        "",
        (
            "| Algorithm | Operation | Input | Key/parameters | Warm-ups | "
            "Repetitions | Mean (ms) | Median (ms) | Std. dev. (ms) |"
        ),
        "|---|---|---:|---|---:|---:|---:|---:|---:|",
    ]

    for result in results:
        case = result.case
        timing = result.timing
        if case.input_size is None:
            input_description = "N/A"
        else:
            input_description = f"{case.input_size} {case.input_unit}"

        lines.append(
            "| "
            + " | ".join(
                (
                    _markdown_text(case.algorithm),
                    _markdown_text(case.operation),
                    _markdown_text(input_description),
                    _markdown_text(case.key_parameters),
                    str(case.warmups),
                    str(timing.repetitions),
                    f"{_milliseconds(timing.mean_ns):.6f}",
                    f"{_milliseconds(timing.median_ns):.6f}",
                    f"{_milliseconds(timing.stdev_ns):.6f}",
                )
            )
            + " |"
        )

    lines.extend(
        (
            "",
            "## Methodology and interpretation",
            "",
            "- Cases were executed sequentially to avoid CPU competition.",
            "- Input/key preparation and unrecorded warm-up calls were excluded.",
            "- Mean, median, and sample standard deviation use recorded samples only.",
            (
                "- DES and AES timings include the detailed trace objects created by "
                "this educational implementation."
            ),
            "- These measurements are not optimized-library performance claims.",
            "- Performance alone does not determine cryptographic security.",
            "",
        )
    )

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_performance_reports(
    results: tuple[BenchmarkResult, ...],
    output_directory: str | Path = DEFAULT_RESULTS_DIRECTORY,
    metadata: EnvironmentMetadata | None = None,
    suite_name: str = "custom",
) -> ExportedReportPaths:
    """Export standard ``performance.csv`` and ``performance.md`` files."""

    # Validate once before creating the output directory. Individual exporters
    # validate again at their public boundary, which keeps them safe when used
    # independently.
    results = _validate_results(results)
    suite_name = _validate_suite_name(suite_name)
    directory = _output_path(output_directory, "Results directory")

    if metadata is None:
        metadata = collect_environment_metadata()
    else:
        metadata = _validate_metadata(metadata)

    directory.mkdir(parents=True, exist_ok=True)
    csv_path = export_performance_csv(
        results,
        directory / "performance.csv",
        metadata,
        suite_name,
    )
    markdown_path = export_performance_markdown(
        results,
        directory / "performance.md",
        metadata,
        suite_name,
    )
    return ExportedReportPaths(csv_path=csv_path, markdown_path=markdown_path)
