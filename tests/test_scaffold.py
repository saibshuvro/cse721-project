"""Smoke tests for the initial project scaffold."""

from __future__ import annotations

import importlib
import unittest

import main


class ScaffoldTests(unittest.TestCase):
    def test_all_algorithm_modules_import(self) -> None:
        modules = (
            "classical.substitution",
            "classical.frequency_analysis",
            "classical.double_transposition",
            "symmetric.des",
            "symmetric.aes",
            "public_key.rsa",
            "public_key.factorization",
            "public_key.ecc",
            "public_key.ecdh",
            "analysis.performance",
            "analysis.security_analysis",
        )
        for module in modules:
            with self.subTest(module=module):
                importlib.import_module(module)

    def test_menu_contains_every_required_algorithm(self) -> None:
        menu = main.render_menu()
        for name in ("Substitution", "Double Transposition", "DES", "AES", "RSA", "ECC"):
            with self.subTest(name=name):
                self.assertIn(name, menu)

    def test_component_numbers_are_unique(self) -> None:
        numbers = [component.number for component in main.COMPONENTS]
        self.assertEqual(len(numbers), len(set(numbers)))


if __name__ == "__main__":
    unittest.main()

