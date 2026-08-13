"""Tests to enable gradually while implementing double_transposition.py."""

from __future__ import annotations

import unittest

from classical import double_transposition


ROW_KEY = (1, 0)
COLUMN_KEY = (2, 0, 1)


class PermutationKeyTests(unittest.TestCase):
    # Remove each skip only after implementing the functions named by it.

    def test_one_based_key_is_parsed(self) -> None:
        self.assertEqual(
            double_transposition.parse_permutation_key("3 1 2", "Row key"),
            (2, 0, 1),
        )

    def test_invalid_permutations_are_rejected(self) -> None:
        invalid_keys = (
            (),
            (0, 0, 1),
            (0, 1, 3),
            (-1, 0, 1),
        )
        for key in invalid_keys:
            with self.subTest(key=key), self.assertRaises((TypeError, ValueError)):
                double_transposition.validate_permutation(key)

    def test_invalid_key_text_is_rejected(self) -> None:
        invalid_texts = (
            "",
            "   ",
            "1 two 3",
            "1 1 2",
            "1 2 4",
        )
        for text in invalid_texts:
            with self.subTest(text=text), self.assertRaises(ValueError):
                double_transposition.parse_permutation_key(text, "Column key")

        with self.assertRaises(TypeError):
            double_transposition.parse_permutation_key(312)  # type: ignore[arg-type]

    def test_inverse_permutation_restores_sequence(self) -> None:
        key = (2, 0, 3, 1)
        inverse = double_transposition.inverse_permutation(key)
        original = ("A", "B", "C", "D")
        permuted = tuple(original[index] for index in key)
        restored = tuple(permuted[index] for index in inverse)
        self.assertEqual(restored, original)


class GridTests(unittest.TestCase):
    def test_padding_records_only_required_characters(self) -> None:
        self.assertEqual(double_transposition.pad_plaintext("HELLO", 6), ("HELLO~", 1))
        self.assertEqual(double_transposition.pad_plaintext("ABCDEF", 6), ("ABCDEF", 0))

    def test_grid_and_text_are_inverses(self) -> None:
        grid = double_transposition.text_to_grid("ABCDEF", 2, 3)
        self.assertEqual(grid, (("A", "B", "C"), ("D", "E", "F")))
        self.assertEqual(double_transposition.grid_to_text(grid), "ABCDEF")

    def test_fixed_grid_permutation(self) -> None:
        grid = (("A", "B", "C"), ("D", "E", "F"))
        after_rows = double_transposition.permute_rows(grid, ROW_KEY)
        after_columns = double_transposition.permute_columns(after_rows, COLUMN_KEY)
        self.assertEqual(after_rows, (("D", "E", "F"), ("A", "B", "C")))
        self.assertEqual(after_columns, (("F", "D", "E"), ("C", "A", "B")))


class DoubleTranspositionTests(unittest.TestCase):
    def test_known_encryption_example(self) -> None:
        ciphertext, trace = double_transposition.encrypt("ABCDEF", ROW_KEY, COLUMN_KEY)
        self.assertEqual(ciphertext, "FDECAB")
        self.assertEqual(trace.padding_length, 0)
        self.assertEqual(len(trace.blocks), 1)
        self.assertEqual(trace.operation, "encrypt")
        self.assertEqual(
            trace.blocks[0].after_second_step,
            (("F", "D", "E"), ("C", "A", "B")),
        )

    def test_empty_plaintext_has_an_empty_trace(self) -> None:
        ciphertext, trace = double_transposition.encrypt("", ROW_KEY, COLUMN_KEY)
        self.assertEqual(ciphertext, "")
        self.assertEqual(trace.blocks, ())
        self.assertEqual(trace.padding_length, 0)

    def test_padded_multiblock_round_trip(self) -> None:
        plaintext = "ABCDEFGHIJK"
        ciphertext, encryption_trace = double_transposition.encrypt(
            plaintext,
            ROW_KEY,
            COLUMN_KEY,
        )
        recovered, decryption_trace = double_transposition.decrypt(
            ciphertext,
            ROW_KEY,
            COLUMN_KEY,
            encryption_trace.padding_length,
        )
        self.assertEqual(recovered, plaintext)
        self.assertEqual(len(encryption_trace.blocks), 2)
        self.assertEqual(len(decryption_trace.blocks), 2)
        self.assertEqual(decryption_trace.operation, "decrypt")

    def test_known_ciphertext_decrypts_without_padding(self) -> None:
        plaintext, trace = double_transposition.decrypt(
            "FDECAB",
            ROW_KEY,
            COLUMN_KEY,
            0,
        )
        self.assertEqual(plaintext, "ABCDEF")
        self.assertEqual(
            trace.blocks[0].after_second_step,
            (("A", "B", "C"), ("D", "E", "F")),
        )

    def test_decryption_rejects_invalid_length_and_padding(self) -> None:
        with self.assertRaises(ValueError):
            double_transposition.decrypt("ABC", ROW_KEY, COLUMN_KEY, 0)

        with self.assertRaises(ValueError):
            double_transposition.decrypt("FDECAB", ROW_KEY, COLUMN_KEY, 1)

        with self.assertRaises(ValueError):
            double_transposition.decrypt("FDECAB", ROW_KEY, COLUMN_KEY, 6)

    def test_transposition_preserves_letter_counts(self) -> None:
        plaintext = "Meet me at noon."
        ciphertext, trace = double_transposition.encrypt(plaintext, ROW_KEY, COLUMN_KEY)
        comparison = double_transposition.compare_letter_frequencies(plaintext, ciphertext)
        self.assertTrue(all(before == after for before, after in comparison.values()))
        self.assertGreaterEqual(trace.padding_length, 0)


if __name__ == "__main__":
    unittest.main()
