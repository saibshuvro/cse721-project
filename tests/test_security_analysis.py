"""Tests for the structured six-component security comparison."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from analysis.security_analysis import (
    SECURITY_ASSESSMENTS,
    SECURITY_REFERENCES,
    SecurityAssessment,
    SecurityReference,
    export_security_markdown,
    render_security_markdown,
    render_terminal_security_comparison,
    validate_security_comparison,
)


class SecurityAssessmentTests(unittest.TestCase):
    def test_default_comparison_contains_exactly_all_six_components(self) -> None:
        validated = validate_security_comparison()

        self.assertEqual(validated, SECURITY_ASSESSMENTS)
        self.assertEqual(
            {assessment.identifier for assessment in validated},
            {
                "substitution",
                "double-transposition",
                "des",
                "aes-128",
                "rsa",
                "ecc-ecdh",
            },
        )
        self.assertEqual(len(validated), 6)

    def test_required_security_distinctions_are_explicit(self) -> None:
        by_identifier = {
            assessment.identifier: assessment for assessment in SECURITY_ASSESSMENTS
        }

        self.assertIn("26!", by_identifier["substitution"].security_basis)
        self.assertIn("r! × c!", by_identifier["double-transposition"].security_basis)
        self.assertIn("56 effective bits", by_identifier["des"].project_parameters)
        self.assertIn("ECB", by_identifier["aes-128"].primary_weakness)
        self.assertIn("OAEP", by_identifier["rsa"].implementation_limitations)
        self.assertIn("18 private scalars", by_identifier["ecc-ecdh"].effective_strength)
        self.assertIn("KDF", by_identifier["ecc-ecdh"].implementation_limitations)

    def test_unknown_reference_is_rejected(self) -> None:
        original = SECURITY_ASSESSMENTS[0]
        invalid_assessment = SecurityAssessment(
            identifier=original.identifier,
            algorithm=original.algorithm,
            category=original.category,
            project_parameters=original.project_parameters,
            security_basis=original.security_basis,
            effective_strength=original.effective_strength,
            demonstrated_analysis=original.demonstrated_analysis,
            primary_weakness=original.primary_weakness,
            implementation_limitations=original.implementation_limitations,
            conclusion=original.conclusion,
            reference_ids=("missing-reference",),
        )

        with self.assertRaises(ValueError):
            validate_security_comparison(
                (invalid_assessment,),
                SECURITY_REFERENCES,
            )

    def test_record_validation_rejects_empty_and_duplicate_data(self) -> None:
        with self.assertRaises(ValueError):
            SecurityReference(identifier="", title="Title", url="https://example.com")

        original = SECURITY_ASSESSMENTS[0]
        with self.assertRaises(ValueError):
            SecurityAssessment(
                identifier=original.identifier,
                algorithm=original.algorithm,
                category=original.category,
                project_parameters=original.project_parameters,
                security_basis=original.security_basis,
                effective_strength=original.effective_strength,
                demonstrated_analysis=original.demonstrated_analysis,
                primary_weakness=original.primary_weakness,
                implementation_limitations=original.implementation_limitations,
                conclusion=original.conclusion,
                reference_ids=("project-scope", "project-scope"),
            )


class SecurityRenderingTests(unittest.TestCase):
    def test_terminal_output_is_wrapped_and_contains_every_algorithm(self) -> None:
        rendered = render_terminal_security_comparison(width=80)

        self.assertIn("Comparative Security Analysis", rendered)
        for assessment in SECURITY_ASSESSMENTS:
            self.assertIn(assessment.algorithm, rendered)
        self.assertTrue(all(len(line) <= 80 for line in rendered.splitlines()))

        with self.assertRaises(ValueError):
            render_terminal_security_comparison(width=40)
        with self.assertRaises(TypeError):
            render_terminal_security_comparison(width=True)

    def test_markdown_has_summary_details_and_authoritative_references(self) -> None:
        rendered = render_security_markdown()

        self.assertIn("## Summary", rendered)
        self.assertIn("## Detailed assessments", rendered)
        self.assertIn("## References", rendered)
        self.assertIn("NIST FIPS 197", rendered)
        self.assertIn("RFC 8017", rendered)
        self.assertIn("SP 800-56A Rev. 3", rendered)
        self.assertIn("None of these from-scratch implementations", rendered)

    def test_markdown_export_creates_parent_directory_and_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "results" / "security_analysis.md"
            returned_path = export_security_markdown(path)

            self.assertEqual(returned_path, path)
            self.assertTrue(path.is_file())
            contents = path.read_text(encoding="utf-8")

        self.assertIn("Substitution Cipher", contents)
        self.assertIn("ECC / ECDH", contents)


if __name__ == "__main__":
    unittest.main()
