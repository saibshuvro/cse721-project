"""Tests for benchmark cases that connect all project components."""

from __future__ import annotations

import unittest

from analysis.benchmark_cases import build_benchmark_cases
from public_key.ecc import Point


class BenchmarkCaseBuilderTests(unittest.TestCase):
    def test_default_cases_cover_all_components_and_have_unique_labels(self) -> None:
        cases = build_benchmark_cases()

        expected_counts = {
            "Substitution": 16,
            "Double Transposition": 12,
            "DES": 9,
            "AES-128": 9,
            "RSA": 16,
            "ECC/ECDH": 4,
        }
        actual_counts = {
            algorithm: sum(case.algorithm == algorithm for case in cases)
            for algorithm in expected_counts
        }

        self.assertEqual(actual_counts, expected_counts)
        self.assertEqual(len(cases), 66)
        self.assertEqual(len({case.label for case in cases}), len(cases))
        self.assertTrue(all(callable(case.prepare) for case in cases))

    def test_representative_decryption_cases_use_untimed_setup(self) -> None:
        cases = build_benchmark_cases(
            message_sizes=(8,),
            rsa_message_sizes=(8,),
            rsa_key_sizes=(32,),
            reduced_alphabet_sizes=(3,),
            repetitions=1,
            slow_repetitions=1,
        )

        substitution_case = self._find_case(cases, "Substitution", "decrypt")
        substitution_plaintext = substitution_case.prepare()()
        self.assertIsInstance(substitution_plaintext, str)
        self.assertEqual(len(substitution_plaintext), 8)

        transposition_case = self._find_case(
            cases,
            "Double Transposition",
            "decrypt",
        )
        transposition_plaintext, _ = transposition_case.prepare()()
        self.assertEqual(transposition_plaintext, substitution_plaintext)

        des_case = self._find_case(cases, "DES", "ECB decrypt")
        des_plaintext, _ = des_case.prepare()()
        self.assertEqual(des_plaintext.decode("ascii"), substitution_plaintext)

        aes_case = self._find_case(cases, "AES-128", "ECB decrypt")
        aes_plaintext, _ = aes_case.prepare()()
        self.assertEqual(aes_plaintext.decode("ascii"), substitution_plaintext)

        rsa_case = self._find_case(cases, "RSA", "text decrypt")
        rsa_plaintext = rsa_case.prepare()()
        self.assertEqual(rsa_plaintext, substitution_plaintext)

    def test_attack_and_ecdh_cases_execute_on_educational_parameters(self) -> None:
        cases = build_benchmark_cases(
            message_sizes=(8,),
            rsa_message_sizes=(8,),
            rsa_key_sizes=(32,),
            reduced_alphabet_sizes=(3,),
            repetitions=1,
            slow_repetitions=1,
        )

        reduced_attack = self._find_case(
            cases,
            "Substitution",
            "reduced brute-force attack",
        )
        candidates = reduced_attack.prepare()()
        self.assertEqual(len(candidates), 6)

        rsa_attacks = [
            case
            for case in cases
            if case.algorithm == "RSA" and case.operation == "factorization attack"
        ]
        self.assertEqual(len(rsa_attacks), 2)
        self.assertTrue(all(isinstance(case.prepare()(), int) for case in rsa_attacks))

        shared_point_case = self._find_case(
            cases,
            "ECC/ECDH",
            "shared-point derivation",
        )
        self.assertIsInstance(shared_point_case.prepare()(), Point)

    def test_invalid_case_dimensions_are_rejected_before_execution(self) -> None:
        with self.assertRaises(TypeError):
            build_benchmark_cases(message_sizes=[16])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            build_benchmark_cases(message_sizes=(0,))
        with self.assertRaises(ValueError):
            build_benchmark_cases(reduced_alphabet_sizes=(9,))
        with self.assertRaises(ValueError):
            build_benchmark_cases(rsa_key_sizes=(33,))
        with self.assertRaises(TypeError):
            build_benchmark_cases(repetitions=True)

    @staticmethod
    def _find_case(cases, algorithm: str, operation: str):
        matches = [
            case
            for case in cases
            if case.algorithm == algorithm and case.operation == operation
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"Expected one {algorithm}/{operation} case, found {len(matches)}"
            )
        return matches[0]


if __name__ == "__main__":
    unittest.main()
