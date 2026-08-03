"""Tests to enable gradually while implementing substitution.py."""

from __future__ import annotations

import math
import unittest

from classical import frequency_analysis
from classical import substitution


# The same example permutation used in the assignment-style documentation:
# A->Q, B->W, C->E, ..., Z->M.
EXAMPLE_KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"


class SubstitutionCipherTests(unittest.TestCase):
    # Remove one skip decorator after implementing the function(s) named by it.

    @unittest.skip("Student TODO: implement validate_key")
    def test_key_is_normalized(self) -> None:
        self.assertEqual(substitution.validate_key(EXAMPLE_KEY.lower()), EXAMPLE_KEY)

    @unittest.skip("Student TODO: implement validate_key")
    def test_invalid_keys_are_rejected(self) -> None:
        invalid_keys = (
            "ABC",                         # too short
            "ABCDEFGHIJKLMNOPQRSTUVWXYA",  # duplicate A; missing Z
            "ABCDEFGHIJKLMNOPQRSTUVWXY1",  # non-letter character
            "ABCDEFGHIJKLMNOPQRSTUVWXY ",  # whitespace is not silently removed
        )
        for key in invalid_keys:
            with self.subTest(key=key), self.assertRaises(ValueError):
                substitution.validate_key(key)

        with self.assertRaises(TypeError):
            substitution.validate_key(3)  # type: ignore[arg-type]

    @unittest.skip("Student TODO: implement both mapping builders")
    def test_complete_forward_and_inverse_mappings(self) -> None:
        encryption = substitution.build_encryption_mapping(EXAMPLE_KEY)
        decryption = substitution.build_decryption_mapping(EXAMPLE_KEY)

        self.assertEqual(len(encryption), 26)
        self.assertEqual(encryption["A"], "Q")
        self.assertEqual(encryption["Z"], "M")
        self.assertEqual(decryption["Q"], "A")
        self.assertEqual(decryption["M"], "Z")

    @unittest.skip("Student TODO: implement encrypt and character translation")
    def test_encrypt_preserves_case_and_non_letters(self) -> None:
        self.assertEqual(
            substitution.encrypt("Attack at Dawn! 123", EXAMPLE_KEY),
            "Qzzqea qz Rqvf! 123",
        )

    @unittest.skip("Student TODO: implement encrypt and decrypt")
    def test_round_trip(self) -> None:
        plaintext = "Meet me at 10:30 PM."
        ciphertext = substitution.encrypt(plaintext, EXAMPLE_KEY)
        self.assertEqual(substitution.decrypt(ciphertext, EXAMPLE_KEY), plaintext)

    def test_reduced_brute_force_tries_every_permutation(self) -> None:
        candidates = substitution.brute_force_reduced("BCA", "ABC")
        self.assertEqual(len(candidates), math.factorial(3))
        self.assertIn(("BCA", "ABC"), candidates)


class FrequencyAnalysisTests(unittest.TestCase):
    @unittest.skip("Student TODO: implement letter_counts")
    def test_letter_counts_ignore_case_and_punctuation(self) -> None:
        counts = frequency_analysis.letter_counts("Aa, B!")
        self.assertEqual(counts["A"], 2)
        self.assertEqual(counts["B"], 1)
        self.assertEqual(counts["Z"], 0)
        self.assertEqual(sum(counts.values()), 3)

    @unittest.skip("Student TODO: implement letter_percentages")
    def test_empty_frequency_input_does_not_divide_by_zero(self) -> None:
        percentages = frequency_analysis.letter_percentages("123!")
        self.assertTrue(all(value == 0.0 for value in percentages.values()))

    @unittest.skip("Student TODO: implement ranked_letters and suggest_english_mapping")
    def test_frequency_mapping_uses_english_rank_order(self) -> None:
        suggestion = frequency_analysis.suggest_english_mapping("ZZZZ YYY XX")
        self.assertEqual(suggestion["Z"], "E")
        self.assertEqual(suggestion["Y"], "T")
        self.assertEqual(suggestion["X"], "A")


if __name__ == "__main__":
    unittest.main()
