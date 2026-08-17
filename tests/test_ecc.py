"""Staged tests for the guided ECC arithmetic and ECDH implementation."""

from __future__ import annotations

import unittest

from public_key import ecc, ecdh


class ECCConfigurationTests(unittest.TestCase):
    """Protect the documented small-curve coursework assumptions."""

    def test_default_domain_parameters_are_explicit(self) -> None:
        curve = ecc.DEFAULT_CURVE

        self.assertEqual(curve.prime, 17)
        self.assertEqual(curve.a, 2)
        self.assertEqual(curve.b, 2)
        self.assertEqual(curve.generator, ecc.Point(5, 1))
        self.assertEqual(curve.order, 19)
        self.assertIs(ecc.INFINITY, None)
        self.assertGreaterEqual(ecc.MAX_ENUMERATION_PRIME, curve.prime)


class ECCFoundationTests(unittest.TestCase):
    def test_integer_primality_and_modular_inverse_helpers(self) -> None:
        self.assertEqual(ecc._require_integer(5, "value", minimum=0), 5)
        with self.assertRaises(TypeError):
            ecc._require_integer(True, "value")
        with self.assertRaises(TypeError):
            ecc._require_integer("5", "value")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ecc._require_integer(-1, "value", minimum=0)

        for prime in (2, 3, 5, 17, 19):
            with self.subTest(prime=prime):
                self.assertTrue(ecc.is_prime(prime))
        for composite in (-1, 0, 1, 4, 15, 21):
            with self.subTest(composite=composite):
                self.assertFalse(ecc.is_prime(composite))

        self.assertEqual(ecc.modular_inverse(5, 17), 7)
        self.assertEqual(ecc.modular_inverse(-3, 17), 11)
        with self.assertRaises(ValueError):
            ecc.modular_inverse(6, 9)


class ECCCurveValidationTests(unittest.TestCase):
    def test_curve_validation_accepts_default_and_rejects_bad_parameters(self) -> None:
        ecc.DEFAULT_CURVE.validate()

        invalid_curves = (
            ecc.Curve(prime=15, a=2, b=2),
            ecc.Curve(prime=3, a=1, b=1),
            ecc.Curve(prime=17, a=17, b=2),
            ecc.Curve(prime=17, a=0, b=0),
            ecc.Curve(prime=17, a=2, b=2, generator=ecc.Point(5, 1)),
            ecc.Curve(prime=17, a=2, b=2, order=19),
            ecc.Curve(
                prime=17,
                a=2,
                b=2,
                generator=ecc.Point(1, 1),
                order=19,
            ),
            ecc.Curve(
                prime=17,
                a=2,
                b=2,
                generator=ecc.Point(5, 1),
                order=17,
            ),
        )
        for curve in invalid_curves:
            with self.subTest(curve=curve), self.assertRaises((TypeError, ValueError)):
                curve.validate()


class ECCMembershipTests(unittest.TestCase):
    def test_membership_uses_canonical_coordinates(self) -> None:
        curve = ecc.DEFAULT_CURVE

        self.assertTrue(curve.contains(ecc.INFINITY))
        self.assertTrue(curve.contains(ecc.Point(5, 1)))
        self.assertTrue(curve.contains(ecc.Point(5, 16)))
        self.assertFalse(curve.contains(ecc.Point(1, 1)))
        self.assertFalse(curve.contains(ecc.Point(22, 1)))
        self.assertFalse(curve.contains(ecc.Point(True, 1)))

        self.assertEqual(
            curve._require_point(ecc.Point(5, 1), "point"),
            ecc.Point(5, 1),
        )
        with self.assertRaises(ValueError):
            curve._require_point(ecc.INFINITY, "point", allow_infinity=False)
        with self.assertRaises(ValueError):
            curve._require_point(ecc.Point(1, 1), "point")


class ECCGroupLawTests(unittest.TestCase):
    def test_identity_inverse_doubling_and_distinct_addition(self) -> None:
        curve = ecc.DEFAULT_CURVE
        generator = ecc.Point(5, 1)

        self.assertEqual(curve.negate(generator), ecc.Point(5, 16))
        self.assertIs(curve.negate(ecc.INFINITY), ecc.INFINITY)
        self.assertEqual(curve.add(ecc.INFINITY, generator), generator)
        self.assertEqual(curve.add(generator, ecc.INFINITY), generator)
        self.assertIs(curve.add(generator, curve.negate(generator)), ecc.INFINITY)
        self.assertEqual(curve.add(generator, generator), ecc.Point(6, 3))
        self.assertEqual(
            curve.add(generator, ecc.Point(6, 3)),
            ecc.Point(10, 6),
        )

        # On y^2 = x^3 + x over F_5, (0, 0) is its own inverse. Its tangent
        # is vertical, so doubling it must produce the point at infinity.
        y_zero_curve = ecc.Curve(prime=5, a=1, b=0)
        self.assertIs(
            y_zero_curve.add(ecc.Point(0, 0), ecc.Point(0, 0)),
            ecc.INFINITY,
        )

    def test_scalar_multiplication_handles_sign_zero_and_order(self) -> None:
        curve = ecc.DEFAULT_CURVE
        generator = ecc.Point(5, 1)

        self.assertIs(curve.multiply(0, generator), ecc.INFINITY)
        self.assertEqual(curve.multiply(1, generator), generator)
        self.assertEqual(curve.multiply(2, generator), ecc.Point(6, 3))
        self.assertEqual(curve.multiply(3, generator), ecc.Point(10, 6))
        self.assertEqual(curve.multiply(-1, generator), ecc.Point(5, 16))
        self.assertEqual(curve.multiply(18, generator), ecc.Point(5, 16))
        self.assertIs(curve.multiply(19, generator), ecc.INFINITY)
        self.assertEqual(curve.multiply(20, generator), generator)


class ECCEnumerationTests(unittest.TestCase):
    def test_enumeration_lists_infinity_and_all_affine_points(self) -> None:
        expected = (
            ecc.INFINITY,
            ecc.Point(0, 6),
            ecc.Point(0, 11),
            ecc.Point(3, 1),
            ecc.Point(3, 16),
            ecc.Point(5, 1),
            ecc.Point(5, 16),
            ecc.Point(6, 3),
            ecc.Point(6, 14),
            ecc.Point(7, 6),
            ecc.Point(7, 11),
            ecc.Point(9, 1),
            ecc.Point(9, 16),
            ecc.Point(10, 6),
            ecc.Point(10, 11),
            ecc.Point(13, 7),
            ecc.Point(13, 10),
            ecc.Point(16, 4),
            ecc.Point(16, 13),
        )

        self.assertEqual(ecc.DEFAULT_CURVE.enumerate_points(), expected)

        too_large = ecc.Curve(
            prime=1_009,
            a=0,
            b=7,
        )
        with self.assertRaises(ValueError):
            too_large.enumerate_points()

    def test_generator_order_matches_domain_parameter(self) -> None:
        curve = ecc.DEFAULT_CURVE

        self.assertEqual(curve.point_order(ecc.INFINITY), 1)
        self.assertEqual(curve.point_order(ecc.Point(5, 1)), 19)


class ECDHTests(unittest.TestCase):
    def test_private_keys_are_bounded_by_subgroup_order(self) -> None:
        curve = ecc.DEFAULT_CURVE

        self.assertEqual(ecdh._validate_private_key(curve, 1), 1)
        self.assertEqual(ecdh._validate_private_key(curve, 18), 18)
        for invalid in (0, 19, -1):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ecdh._validate_private_key(curve, invalid)
        with self.assertRaises(TypeError):
            ecdh._validate_private_key(curve, True)

        for _ in range(100):
            generated = ecdh.generate_private_key(curve)
            self.assertGreaterEqual(generated, 1)
            self.assertLess(generated, 19)

    def test_known_private_scalars_produce_known_public_points(self) -> None:
        curve = ecc.DEFAULT_CURVE

        self.assertEqual(ecdh.public_key(curve, 5), ecc.Point(9, 16))
        self.assertEqual(ecdh.public_key(curve, 7), ecc.Point(0, 6))

    def test_alice_and_bob_derive_the_same_shared_point_and_x(self) -> None:
        curve = ecc.DEFAULT_CURVE
        alice_private = 5
        bob_private = 7
        alice_public = ecdh.public_key(curve, alice_private)
        bob_public = ecdh.public_key(curve, bob_private)

        alice_shared = ecdh.shared_point(curve, alice_private, bob_public)
        bob_shared = ecdh.shared_point(curve, bob_private, alice_public)

        self.assertEqual(alice_shared, ecc.Point(10, 11))
        self.assertEqual(bob_shared, alice_shared)
        self.assertEqual(
            ecdh.shared_secret_x(curve, alice_private, bob_public),
            10,
        )

    def test_invalid_or_wrong_subgroup_public_points_are_rejected(self) -> None:
        curve = ecc.DEFAULT_CURVE

        for invalid in (
            ecc.INFINITY,
            ecc.Point(1, 1),
            ecc.Point(22, 1),
        ):
            with self.subTest(invalid=invalid), self.assertRaises((TypeError, ValueError)):
                ecdh.shared_point(curve, 5, invalid)

        # This curve has 6 points. G=(0,1) has prime order 3, while (4,0)
        # has order 2. The latter is on the curve but outside G's subgroup.
        cofactor_curve = ecc.Curve(
            prime=5,
            a=0,
            b=1,
            generator=ecc.Point(0, 1),
            order=3,
        )
        wrong_subgroup_point = ecc.Point(4, 0)
        self.assertTrue(cofactor_curve.contains(wrong_subgroup_point))
        with self.assertRaises(ValueError):
            ecdh.shared_point(cofactor_curve, 1, wrong_subgroup_point)


if __name__ == "__main__":
    unittest.main()
