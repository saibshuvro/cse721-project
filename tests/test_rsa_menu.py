"""Scripted terminal tests for the RSA submenu and main dispatch."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from typing import Iterable
from unittest.mock import patch

import main
from cli.rsa_menu import _parse_ciphertext_blocks, run_rsa_menu
from public_key import rsa


# Fixed 128-bit educational key used only to make menu tests fast and
# deterministic. The real menu accepts the assignment's 512/1024-bit choices.
EXAMPLE_KEYPAIR = rsa.KeyPair(
    public=rsa.PublicKey(
        exponent=65_537,
        modulus=243_660_041_575_229_266_446_822_643_661_206_902_679,
    ),
    private=rsa.PrivateKey(
        exponent=9_123_727_696_196_234_490_192_599_739_981_688_673,
        modulus=243_660_041_575_229_266_446_822_643_661_206_902_679,
    ),
    prime_p=16_576_410_857_080_070_201,
    prime_q=14_699_203_806_905_996_879,
)


def scripted_input(responses: Iterable[str]):
    """Return an ``input`` replacement that consumes predefined responses."""

    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


class RSAMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_rsa_menu(scripted_input(responses))
        return output.getvalue()

    def test_generate_key_displays_public_and_private_components(self) -> None:
        with patch(
            "cli.rsa_menu.rsa.generate_keypair",
            return_value=EXAMPLE_KEYPAIR,
        ) as generate_keypair:
            output = self.run_menu(("1", "512", "5"))

        generate_keypair.assert_called_once_with(512)
        self.assertIn("Generated RSA modulus size: 128 bits", output)
        self.assertIn("Public key (n, e):", output)
        self.assertIn(f"e: {EXAMPLE_KEYPAIR.public.exponent}", output)
        self.assertIn("Private key (n, d):", output)
        self.assertIn(f"d: {EXAMPLE_KEYPAIR.private.exponent}", output)
        self.assertIn("primes are intentionally not displayed", output)

    def test_generate_then_encrypt_displays_decimal_and_hex_blocks(self) -> None:
        plaintext = "Hello বাংলা"
        expected = rsa.encrypt_text(plaintext, EXAMPLE_KEYPAIR.public)

        with patch(
            "cli.rsa_menu.rsa.generate_keypair",
            return_value=EXAMPLE_KEYPAIR,
        ):
            output = self.run_menu(("1", "512", "2", plaintext, "5"))

        self.assertIn(f"RSA ciphertext block count: {len(expected)}", output)
        for block in expected:
            self.assertIn(str(block), output)
            self.assertIn(f"0x{block:X}", output)
        self.assertIn("textbook RSA is deterministic", output)
        self.assertIn("does not implement OAEP", output)

    def test_decryption_accepts_mixed_decimal_and_hex_blocks(self) -> None:
        plaintext = "Hello বাংলা"
        ciphertext = rsa.encrypt_text(plaintext, EXAMPLE_KEYPAIR.public)
        displayed_blocks = [str(ciphertext[0])]
        displayed_blocks.extend(f"0x{block:X}" for block in ciphertext[1:])

        with patch(
            "cli.rsa_menu.rsa.generate_keypair",
            return_value=EXAMPLE_KEYPAIR,
        ):
            output = self.run_menu(
                ("1", "512", "3", ", ".join(displayed_blocks), "5")
            )

        self.assertIn(f"Ciphertext blocks decrypted: {len(ciphertext)}", output)
        self.assertIn(f"Decrypted plaintext: {plaintext}", output)

    def test_factorization_demo_recovers_factors_and_private_exponent(self) -> None:
        output = self.run_menu(("4", "5"))

        self.assertIn("Public modulus n: 3233", output)
        self.assertIn("Recovered factors: p=53, q=61", output)
        self.assertIn("Reconstructed phi(n): 3120", output)
        self.assertIn("Recovered private exponent d: 2753", output)
        self.assertIn("Decrypted example integer: 65", output)
        self.assertIn("not practical against the normal 512/1024-bit key", output)

    def test_encrypt_without_key_reports_workflow_error(self) -> None:
        output = self.run_menu(("2", "5"))

        self.assertIn("Error: Generate a key pair with option 1 first", output)
        self.assertGreaterEqual(output.count("Educational textbook RSA"), 2)

    def test_invalid_key_size_returns_to_rsa_menu(self) -> None:
        output = self.run_menu(("1", "2048", "5"))

        self.assertIn("Error: Key size must be 512 or 1024 bits", output)
        self.assertGreaterEqual(output.count("Educational textbook RSA"), 2)

    def test_ciphertext_parser_accepts_formats_and_rejects_bad_tokens(self) -> None:
        self.assertEqual(
            _parse_ciphertext_blocks("10, 0x10  0007"),
            [10, 16, 7],
        )
        self.assertEqual(_parse_ciphertext_blocks(""), [])

        for invalid in ("-1", "0x", "12.5", "not-a-number"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                _parse_ciphertext_blocks(invalid)

    def test_main_menu_dispatches_and_returns(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.interactive_menu(scripted_input(("5", "5", "8")))

        self.assertEqual(result, 0)
        self.assertIn("Educational textbook RSA", output.getvalue())

    def test_main_component_marks_rsa_implemented(self) -> None:
        rsa_component = next(item for item in main.COMPONENTS if item.number == "5")
        self.assertTrue(rsa_component.implemented)


if __name__ == "__main__":
    unittest.main()
