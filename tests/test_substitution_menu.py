"""Scripted terminal tests for the substitution submenu and main dispatch."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from typing import Iterable

import main
from cli.substitution_menu import run_substitution_menu


EXAMPLE_KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"


def scripted_input(responses: Iterable[str]):
    """Return an ``input`` replacement that consumes predefined responses."""

    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


class SubstitutionMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_substitution_menu(scripted_input(responses))
        return output.getvalue()

    def test_encrypt_operation_displays_mapping_and_ciphertext(self) -> None:
        output = self.run_menu(("1", "Attack at Dawn!", EXAMPLE_KEY, "5"))
        self.assertIn("Plain : A B C", output)
        self.assertIn("Cipher: Q W E", output)
        self.assertIn("Ciphertext: Qzzqea qz Rqvf!", output)

    def test_decrypt_operation_displays_plaintext(self) -> None:
        output = self.run_menu(("2", "Qzzqea qz Rqvf!", EXAMPLE_KEY, "5"))
        self.assertIn("Decrypted plaintext: Attack at Dawn!", output)

    def test_invalid_key_returns_to_submenu(self) -> None:
        output = self.run_menu(("1", "Hello", "ABC", "5"))
        self.assertIn("Error: Key must be exactly 26 letters long", output)
        self.assertGreaterEqual(output.count("Substitution Cipher"), 2)

    def test_brute_force_reports_all_toy_candidates(self) -> None:
        output = self.run_menu(("3", "BCA", "ABC", "5"))
        self.assertIn("Total candidate keys tested: 6", output)
        self.assertIn("Key BCA -> ABC", output)

    def test_frequency_analysis_displays_mapping_and_preview(self) -> None:
        output = self.run_menu(("4", "ZZZZ YYY XX", "5"))
        self.assertIn("Z->E", output)
        self.assertIn("Y->T", output)
        self.assertIn("X->A", output)
        self.assertIn("Frequency-based preview: EEEE TTT AA", output)

    def test_main_menu_dispatches_to_substitution_and_returns(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.interactive_menu(scripted_input(("1", "5", "8")))

        self.assertEqual(result, 0)
        self.assertIn("Substitution Cipher", output.getvalue())


if __name__ == "__main__":
    unittest.main()
