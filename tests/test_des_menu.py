"""Scripted terminal tests for the DES submenu and main dispatch."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from typing import Iterable
from unittest.mock import patch

import main
from cli.des_menu import run_des_menu
from symmetric import des


EXAMPLE_KEY = bytes.fromhex("133457799BBCDFF1")


def scripted_input(responses: Iterable[str]):
    """Return an ``input`` replacement that consumes predefined responses."""

    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


class DESMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_des_menu(scripted_input(responses))
        return output.getvalue()

    def test_generate_key_displays_all_round_keys(self) -> None:
        with patch("cli.des_menu.des.generate_key", return_value=EXAMPLE_KEY):
            output = self.run_menu(("1", "5"))

        self.assertIn("DES key (hex): 133457799BBCDFF1", output)
        self.assertIn("1B02EFFC7072", output)
        self.assertIn("CB3D8B0E17F5", output)
        self.assertIn("Odd parity in every key byte: Yes", output)

    def test_encrypt_text_displays_key_ciphertext_and_block_count(self) -> None:
        expected_ciphertext, _ = des.encrypt_ecb(b"Hello", EXAMPLE_KEY)
        with patch("cli.des_menu.des.generate_key", return_value=EXAMPLE_KEY):
            output = self.run_menu(("2", "Hello", "5"))

        self.assertIn(f"Ciphertext (hex): {expected_ciphertext.hex().upper()}", output)
        self.assertIn("DES key (hex): 133457799BBCDFF1", output)
        self.assertIn("Padded DES blocks encrypted: 1", output)
        self.assertIn("ECB, which leaks patterns", output)

    def test_decrypt_hexadecimal_ciphertext_displays_utf8_text(self) -> None:
        plaintext = "Hello বাংলা"
        ciphertext, _ = des.encrypt_ecb(plaintext.encode(), EXAMPLE_KEY)
        output = self.run_menu(
            ("3", ciphertext.hex(), EXAMPLE_KEY.hex(), "5")
        )

        self.assertIn(f"Decrypted plaintext: {plaintext}", output)
        self.assertIn("DES key (hex): 133457799BBCDFF1", output)

    def test_trace_operation_displays_standard_block_result(self) -> None:
        output = self.run_menu(
            (
                "4",
                EXAMPLE_KEY.hex(),
                "E",
                "0123456789ABCDEF",
                "5",
            )
        )

        self.assertIn("Output block: 85E813540F0AB405", output)
        self.assertIn("Detailed encrypt trace:", output)
        self.assertIn("Preoutput R16 || L16:", output)

    def test_invalid_hex_returns_to_des_menu(self) -> None:
        output = self.run_menu(("3", "not-hex", EXAMPLE_KEY.hex(), "5"))
        self.assertIn("Error: Ciphertext must contain only hexadecimal digits", output)
        self.assertGreaterEqual(output.count("Educational implementation"), 2)

    def test_main_menu_dispatches_and_returns(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.interactive_menu(scripted_input(("3", "5", "8")))

        self.assertEqual(result, 0)
        self.assertIn("Educational implementation: single DES", output.getvalue())

    def test_main_component_marks_des_implemented(self) -> None:
        des_component = next(item for item in main.COMPONENTS if item.number == "3")
        self.assertTrue(des_component.implemented)


if __name__ == "__main__":
    unittest.main()
