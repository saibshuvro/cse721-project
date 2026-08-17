"""Scripted terminal tests for the ECC/ECDH submenu and main dispatch."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from typing import Iterable
from unittest.mock import patch

import main
from cli.ecc_menu import run_ecc_menu


def scripted_input(responses: Iterable[str]):
    """Return an ``input`` replacement that consumes predefined responses."""

    response_iterator = iter(responses)

    def read(_prompt: str) -> str:
        return next(response_iterator)

    return read


class ECCMenuTests(unittest.TestCase):
    def run_menu(self, responses: Iterable[str]) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            run_ecc_menu(scripted_input(responses))
        return output.getvalue()

    def test_domain_parameters_are_validated_and_displayed(self) -> None:
        output = self.run_menu(("1", "6"))

        self.assertIn("Curve equation: y^2 = x^3 + 2x + 2 (mod 17)", output)
        self.assertIn("G (generator): (5, 1)", output)
        self.assertIn("n (generator order): 19", output)
        self.assertIn("nG: infinity", output)
        self.assertIn("Total group points: 19", output)
        self.assertIn("Cofactor h = #E(F_p)/n: 1", output)
        self.assertIn("Domain validation result: valid", output)

    def test_all_curve_points_are_listed(self) -> None:
        output = self.run_menu(("2", "6"))

        self.assertIn("Generator cycle for G = (5, 1):", output)
        self.assertIn(" 1G = (5, 1)", output)
        self.assertIn(" 2G = (6, 3)", output)
        self.assertIn(" 3G = (10, 6)", output)
        self.assertIn("18G = (5, 16)", output)
        self.assertIn("19G = infinity", output)
        self.assertIn("Affine points: 18", output)
        self.assertIn("Total points: 19", output)
        self.assertIn("Generator order n: 19", output)
        self.assertIn("Cofactor h: 1", output)
        self.assertIn("G generates the entire curve group", output)

        # Confirm that the visible order really is scalar order, not the old
        # coordinate-sorted enumeration order.
        self.assertLess(output.index(" 1G = (5, 1)"), output.index(" 2G = (6, 3)"))

    def test_point_inspection_displays_inverse_and_order(self) -> None:
        output = self.run_menu(("3", "5", "1", "6"))

        self.assertIn("P: (5, 1)", output)
        self.assertIn("-P: (5, 16)", output)
        self.assertIn("P + (-P): infinity", output)
        self.assertIn("Order of P: 19", output)
        self.assertIn("19P: infinity", output)

    def test_generated_key_pair_displays_private_and_public_values(self) -> None:
        with patch("cli.ecc_menu.ecdh.generate_private_key", return_value=5):
            output = self.run_menu(("4", "6"))

        self.assertIn("Private key d: 5", output)
        self.assertIn("Public key Q = dG: (9, 16)", output)
        self.assertIn("Subgroup check nQ: infinity", output)
        self.assertIn("19-element group provides no real security", output)

    def test_explicit_private_keys_produce_matching_ecdh_result(self) -> None:
        output = self.run_menu(("5", "5", "7", "6"))

        self.assertIn("Private key dA: 5", output)
        self.assertIn("Public key QA = dA*G: (9, 16)", output)
        self.assertIn("Private key dB: 7", output)
        self.assertIn("Public key QB = dB*G: (0, 6)", output)
        self.assertIn("Alice computes dA*QB: (10, 11)", output)
        self.assertIn("Bob computes dB*QA: (10, 11)", output)
        self.assertIn("Shared points match: Yes", output)
        self.assertIn("raw x-coordinate): 10", output)
        self.assertIn("real protocols use a KDF", output)

    def test_empty_private_inputs_auto_generate_both_scalars(self) -> None:
        with patch(
            "cli.ecc_menu.ecdh.generate_private_key",
            side_effect=(5, 7),
        ):
            output = self.run_menu(("5", "", "", "6"))

        self.assertIn("Private key dA: 5 (auto-generated)", output)
        self.assertIn("Private key dB: 7 (auto-generated)", output)
        self.assertIn("Shared points match: Yes", output)

    def test_invalid_point_returns_to_ecc_menu(self) -> None:
        output = self.run_menu(("3", "1", "1", "6"))

        self.assertIn("Error: Point (1, 1) is not on the curve", output)
        self.assertGreaterEqual(output.count("Educational 19-point curve"), 2)

    def test_invalid_private_key_returns_to_ecc_menu(self) -> None:
        output = self.run_menu(("5", "0", "6"))

        self.assertIn("Error: Private key must be in the interval 1..18", output)
        self.assertGreaterEqual(output.count("Educational 19-point curve"), 2)

    def test_main_menu_dispatches_and_returns(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main.interactive_menu(scripted_input(("6", "6", "8")))

        self.assertEqual(result, 0)
        self.assertIn("Educational 19-point curve", output.getvalue())

    def test_main_component_marks_ecc_implemented(self) -> None:
        ecc_component = next(item for item in main.COMPONENTS if item.number == "6")
        self.assertTrue(ecc_component.implemented)


if __name__ == "__main__":
    unittest.main()
