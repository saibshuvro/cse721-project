"""Staged tests for the guided textbook RSA implementation."""

from __future__ import annotations

import unittest

from public_key import factorization, rsa


class RSAConfigurationTests(unittest.TestCase):
    """Protect the documented coursework assumptions."""

    def test_coursework_defaults_are_explicit(self) -> None:
        self.assertEqual(rsa.DEFAULT_PUBLIC_EXPONENT, 65_537)
        self.assertEqual(rsa.COURSEWORK_KEY_SIZES, (512, 1024))
        self.assertGreaterEqual(rsa.DEFAULT_MILLER_RABIN_ROUNDS, 20)
        self.assertEqual(rsa.TEXT_BLOCK_MARKER, 0x01)


class RSAIntegerValidationTests(unittest.TestCase):
    def test_require_integer_rejects_invalid_types_and_bounds(self) -> None:
        self.assertEqual(rsa._require_integer(5, "value", minimum=0), 5)
        with self.assertRaises(TypeError):
            rsa._require_integer(True, "value")
        with self.assertRaises(TypeError):
            rsa._require_integer("5", "value")
        with self.assertRaises(ValueError):
            rsa._require_integer(-1, "value", minimum=0)


class RSAArithmeticTests(unittest.TestCase):
    def test_gcd_and_bezout_identity(self) -> None:
        self.assertEqual(rsa.greatest_common_divisor(240, 46), 2)
        self.assertEqual(rsa.greatest_common_divisor(-240, 46), 2)
        self.assertEqual(rsa.greatest_common_divisor(0, 0), 0)

        gcd, x_coefficient, y_coefficient = rsa.extended_gcd(240, 46)
        self.assertEqual(gcd, 2)
        self.assertEqual(240 * x_coefficient + 46 * y_coefficient, gcd)

    def test_modular_inverse_exists_only_for_coprime_values(self) -> None:
        self.assertEqual(rsa.modular_inverse(17, 3120), 2753)
        self.assertEqual((17 * rsa.modular_inverse(17, 3120)) % 3120, 1)
        with self.assertRaises(ValueError):
            rsa.modular_inverse(6, 9)

    def test_modular_exponentiation_matches_known_rsa_values(self) -> None:
        self.assertEqual(rsa.modular_exponentiation(65, 17, 3233), 2790)
        self.assertEqual(rsa.modular_exponentiation(2790, 2753, 3233), 65)
        self.assertEqual(rsa.modular_exponentiation(123, 0, 17), 1)
        with self.assertRaises(ValueError):
            rsa.modular_exponentiation(2, -1, 5)
        with self.assertRaises(ValueError):
            rsa.modular_exponentiation(2, 3, 0)


class RSAPrimeTests(unittest.TestCase):
    def test_probable_prime_test_handles_primes_and_composites(self) -> None:
        for prime in (2, 3, 5, 53, 61, 65_537):
            with self.subTest(prime=prime):
                self.assertTrue(rsa.is_probable_prime(prime))

        for composite in (-1, 0, 1, 4, 9, 21, 561, 1105):
            with self.subTest(composite=composite):
                self.assertFalse(rsa.is_probable_prime(composite))

    def test_generated_prime_has_requested_size_and_exponent_condition(self) -> None:
        prime = rsa.generate_probable_prime(32, public_exponent=17)
        self.assertEqual(prime.bit_length(), 32)
        self.assertEqual(prime % 2, 1)
        self.assertEqual(rsa.greatest_common_divisor(prime - 1, 17), 1)
        self.assertTrue(rsa.is_probable_prime(prime))


class RSAKeyGenerationTests(unittest.TestCase):
    def test_generated_keypair_satisfies_rsa_relationships(self) -> None:
        keypair = rsa.generate_keypair(64, public_exponent=17)
        p = keypair.prime_p
        q = keypair.prime_q
        modulus = keypair.public.modulus
        totient = (p - 1) * (q - 1)

        self.assertNotEqual(p, q)
        self.assertEqual(modulus, p * q)
        self.assertEqual(modulus.bit_length(), 64)
        self.assertEqual(keypair.private.modulus, modulus)
        self.assertEqual(keypair.public.exponent, 17)
        self.assertEqual(
            (keypair.public.exponent * keypair.private.exponent) % totient,
            1,
        )


class RSAIntegerPrimitiveTests(unittest.TestCase):
    def test_classic_small_rsa_example_and_range_checks(self) -> None:
        public_key = rsa.PublicKey(exponent=17, modulus=3233)
        private_key = rsa.PrivateKey(exponent=2753, modulus=3233)

        ciphertext = rsa.encrypt_int(65, public_key)
        self.assertEqual(ciphertext, 2790)
        self.assertEqual(rsa.decrypt_int(ciphertext, private_key), 65)

        with self.assertRaises(ValueError):
            rsa.encrypt_int(3233, public_key)
        with self.assertRaises(ValueError):
            rsa.decrypt_int(-1, private_key)


class RSATextTests(unittest.TestCase):
    def test_multiblock_utf8_and_zero_bytes_round_trip(self) -> None:
        keypair = rsa.generate_keypair(128)
        plaintext = "\x00RSA handles UTF-8: বাংলা\x00"

        ciphertext = rsa.encrypt_text(plaintext, keypair.public)
        recovered = rsa.decrypt_text(ciphertext, keypair.private)

        self.assertEqual(recovered, plaintext)
        self.assertTrue(
            all(
                0 <= block < keypair.public.modulus
                for block in ciphertext
            )
        )
        self.assertEqual(rsa.encrypt_text(plaintext, keypair.public), ciphertext)
        self.assertEqual(rsa.encrypt_text("", keypair.public), [])
        self.assertEqual(rsa.decrypt_text([], keypair.private), "")


class RSAFactorizationTests(unittest.TestCase):
    def test_trial_division_recovers_toy_private_exponent(self) -> None:
        self.assertIsNone(factorization.trial_division(3233, max_divisor=50))
        self.assertEqual(
            factorization.trial_division(3233, max_divisor=100),
            (53, 61),
        )
        self.assertEqual(
            factorization.recover_private_exponent(
                modulus=3233,
                public_exponent=17,
                max_divisor=100,
            ),
            2753,
        )


if __name__ == "__main__":
    unittest.main()
