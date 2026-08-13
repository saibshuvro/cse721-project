"""Scripted terminal tests for the Double Transposition submenu."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from typing import Iterable

import main
from cli.double_transposition_menu import run_double_transposition_menu


def scripted_input(responses: Iterable[str]):
    """Return an input replacement that consumes predefined responses."""

    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


class DoubleTranspositionMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_double_transposition_menu(scripted_input(responses))
        return output.getvalue()

    def test_encrypt_displays_intermediate_grids_and_ciphertext(self) -> None:
        output = self.run_menu(("1", "ABCDEF", "2 1", "3 1 2", "4"))
        self.assertIn("Input/padded grid:", output)
        self.assertIn("After row permutation:", output)
        self.assertIn("After column permutation:", output)
        self.assertIn("Padding length: 0", output)
        self.assertIn("Ciphertext: FDECAB", output)

    def test_decrypt_displays_reconstructed_plaintext(self) -> None:
        output = self.run_menu(("2", "FDECAB", "2 1", "3 1 2", "0", "4"))
        self.assertIn("After inverse column permutation:", output)
        self.assertIn("After inverse row permutation:", output)
        self.assertIn("Decrypted plaintext: ABCDEF", output)

    def test_frequency_comparison_explains_preservation(self) -> None:
        output = self.run_menu(("3", "ABCDEF", "FDECAB", "4"))
        self.assertIn("Result: A-Z frequencies are preserved.", output)
        self.assertIn("frequency analysis alone does not reveal", output)

    def test_invalid_key_returns_to_submenu(self) -> None:
        output = self.run_menu(("1", "ABCDEF", "1 1", "3 1 2", "4"))
        self.assertIn("Error: Row key must not contain duplicate values", output)
        self.assertGreaterEqual(output.count("Double Transposition Cipher"), 2)

    def test_invalid_padding_returns_to_submenu(self) -> None:
        output = self.run_menu(("2", "FDECAB", "2 1", "3 1 2", "one", "4"))
        self.assertIn("Error: Padding length must be an integer", output)

    def test_main_menu_dispatches_and_returns(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.interactive_menu(scripted_input(("2", "4", "8")))

        self.assertEqual(result, 0)
        self.assertIn("Double Transposition Cipher", output.getvalue())


if __name__ == "__main__":
    unittest.main()
