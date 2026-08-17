"""Scripted terminal tests for the AES-128 submenu and main dispatch."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from typing import Iterable
from unittest.mock import patch

import main
from cli.aes_menu import run_aes_menu
from symmetric import aes


EXAMPLE_KEY = bytes.fromhex("000102030405060708090A0B0C0D0E0F")


def scripted_input(responses: Iterable[str]):
    """Return an ``input`` replacement that consumes predefined responses."""

    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


class AESMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_aes_menu(scripted_input(responses))
        return output.getvalue()

    def test_generate_key_displays_k0_through_k10(self) -> None:
        with patch("cli.aes_menu.aes.generate_key", return_value=EXAMPLE_KEY):
            output = self.run_menu(("1", "5"))

        self.assertIn("AES-128 key (hex): 000102030405060708090A0B0C0D0E0F", output)
        self.assertIn("D6AA74FDD2AF72FADAA678F1D6AB76FE", output)
        self.assertIn("13111D7FE3944A17F307A78B4D2B30C5", output)
        self.assertIn("Key size: 128 bits", output)

    def test_encrypt_text_displays_key_ciphertext_and_block_count(self) -> None:
        expected_ciphertext, _ = aes.encrypt_ecb(b"Hello", EXAMPLE_KEY)
        with patch("cli.aes_menu.aes.generate_key", return_value=EXAMPLE_KEY):
            output = self.run_menu(("2", "Hello", "5"))

        self.assertIn(
            f"Ciphertext (hex): {expected_ciphertext.hex().upper()}",
            output,
        )
        self.assertIn("AES-128 key (hex): 000102030405060708090A0B0C0D0E0F", output)
        self.assertIn("Padded AES blocks encrypted: 1", output)
        self.assertIn("ECB, which leaks patterns", output)

    def test_decrypt_hexadecimal_ciphertext_displays_utf8_text(self) -> None:
        plaintext = "Hello বাংলা"
        ciphertext, _ = aes.encrypt_ecb(plaintext.encode(), EXAMPLE_KEY)
        output = self.run_menu(
            ("3", ciphertext.hex(), EXAMPLE_KEY.hex(), "5")
        )

        self.assertIn(f"Decrypted plaintext: {plaintext}", output)
        self.assertIn("AES-128 key (hex): 000102030405060708090A0B0C0D0E0F", output)

    def test_trace_operation_displays_fips_block_result(self) -> None:
        output = self.run_menu(
            (
                "4",
                EXAMPLE_KEY.hex(),
                "E",
                "00112233445566778899AABBCCDDEEFF",
                "5",
            )
        )

        self.assertIn("Output block: 69C4E0D86A7B0430D8CDB78070B4C55A", output)
        self.assertIn("Detailed encrypt trace:", output)
        self.assertIn("SubBytes", output)
        self.assertIn("MixColumns", output)
        self.assertIn("Final encrypt output:", output)

    def test_invalid_hex_returns_to_aes_menu(self) -> None:
        output = self.run_menu(("3", "not-hex", EXAMPLE_KEY.hex(), "5"))

        self.assertIn(
            "Error: Ciphertext must contain only hexadecimal digits",
            output,
        )
        self.assertGreaterEqual(output.count("Educational implementation"), 2)

    def test_invalid_key_length_returns_to_aes_menu(self) -> None:
        output = self.run_menu(("4", "0011", "5"))

        self.assertIn(
            "Error: AES-128 key must be exactly 32 hexadecimal digits",
            output,
        )

    def test_decryption_reports_non_utf8_plaintext(self) -> None:
        ciphertext, _ = aes.encrypt_ecb(b"\xFF", EXAMPLE_KEY)
        output = self.run_menu(
            ("3", ciphertext.hex(), EXAMPLE_KEY.hex(), "5")
        )

        self.assertIn("Error: decrypted bytes are not valid UTF-8", output)

    def test_main_menu_dispatches_and_returns(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.interactive_menu(scripted_input(("4", "5", "8")))

        self.assertEqual(result, 0)
        self.assertIn("Educational implementation: AES-ECB", output.getvalue())

    def test_main_component_marks_aes_implemented(self) -> None:
        aes_component = next(item for item in main.COMPONENTS if item.number == "4")
        self.assertTrue(aes_component.implemented)


if __name__ == "__main__":
    unittest.main()
