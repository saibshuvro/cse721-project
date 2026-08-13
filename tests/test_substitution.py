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
    def test_key_is_normalized(self) -> None:
        self.assertEqual(substitution.validate_key(EXAMPLE_KEY.lower()), EXAMPLE_KEY)

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

    def test_complete_forward_and_inverse_mappings(self) -> None:
        encryption = substitution.build_encryption_mapping(EXAMPLE_KEY)
        decryption = substitution.build_decryption_mapping(EXAMPLE_KEY)

        self.assertEqual(len(encryption), 26)
        self.assertEqual(encryption["A"], "Q")
        self.assertEqual(encryption["Z"], "M")
        self.assertEqual(decryption["Q"], "A")
        self.assertEqual(decryption["M"], "Z")

    def test_encrypt_preserves_case_and_non_letters(self) -> None:
        self.assertEqual(
            substitution.encrypt("Attack at Dawn! 123", EXAMPLE_KEY),
            "Qzzqea qz Rqvf! 123",
        )

    def test_non_ascii_characters_are_preserved_without_case_normalization(self) -> None:
        plaintext = "ASCII edge cases: ı ſ ß K; বাংলা"
        ciphertext = substitution.encrypt(plaintext, EXAMPLE_KEY)
        self.assertEqual(
            "".join(
                character
                for character in ciphertext
                if character in "ıſßKবাংলা"
            ),
            "ıſßKবাংলা",
        )
        self.assertEqual(substitution.decrypt(ciphertext, EXAMPLE_KEY), plaintext)

    def test_unicode_ascii_lookalikes_are_rejected_in_keys_and_toy_alphabets(self) -> None:
        identity_key = substitution.ALPHABET
        with self.assertRaises(ValueError):
            substitution.validate_key(identity_key.replace("I", "ı"))
        with self.assertRaises(ValueError):
            substitution.validate_key(identity_key.replace("S", "ſ"))
        with self.assertRaises(ValueError):
            substitution.validate_reduced_alphabet("Aı")

    def test_round_trip(self) -> None:
        plaintext = "Meet me at 10:30 PM."
        ciphertext = substitution.encrypt(plaintext, EXAMPLE_KEY)
        self.assertEqual(substitution.decrypt(ciphertext, EXAMPLE_KEY), plaintext)

    def test_reduced_brute_force_tries_every_permutation(self) -> None:
        candidates = substitution.brute_force_reduced("BCA", "ABC")
        self.assertEqual(len(candidates), math.factorial(3))
        self.assertIn(("BCA", "ABC"), candidates)


class FrequencyAnalysisTests(unittest.TestCase):
    def test_letter_counts_ignore_case_and_punctuation(self) -> None:
        counts = frequency_analysis.letter_counts("Aa, B!")
        self.assertEqual(counts["A"], 2)
        self.assertEqual(counts["B"], 1)
        self.assertEqual(counts["Z"], 0)
        self.assertEqual(sum(counts.values()), 3)

    def test_letter_counts_ignore_non_ascii_case_expansions(self) -> None:
        counts = frequency_analysis.letter_counts("ı ſ ß K")
        self.assertEqual(sum(counts.values()), 0)

    def test_empty_frequency_input_does_not_divide_by_zero(self) -> None:
        percentages = frequency_analysis.letter_percentages("123!")
        self.assertTrue(all(value == 0.0 for value in percentages.values()))

    def test_frequency_mapping_uses_english_rank_order(self) -> None:
        suggestion = frequency_analysis.suggest_english_mapping("ZZZZ YYY XX")
        self.assertEqual(suggestion["Z"], "E")
        self.assertEqual(suggestion["Y"], "T")
        self.assertEqual(suggestion["X"], "A")

    def test_partial_mapping_preserves_case_and_non_letters(self) -> None:
        preview = frequency_analysis.apply_partial_mapping(
            "XyZ! 123",
            {"X": "E", "y": "T"},
        )
        self.assertEqual(preview, "Et_! 123")

    def test_partial_mapping_preserves_non_ascii_and_rejects_lookalikes(self) -> None:
        self.assertEqual(
            frequency_analysis.apply_partial_mapping("X ı ſ ß K", {"X": "E"}),
            "E ı ſ ß K",
        )
        with self.assertRaises(ValueError):
            frequency_analysis.apply_partial_mapping("S", {"ſ": "E"})

    def test_partial_mapping_rejects_duplicate_plaintext_letters(self) -> None:
        with self.assertRaises(ValueError):
            frequency_analysis.apply_partial_mapping(
                "XY",
                {"X": "E", "Y": "e"},
            )


if __name__ == "__main__":
    unittest.main()
