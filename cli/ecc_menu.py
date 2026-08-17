"""Interactive terminal menu for educational ECC arithmetic and ECDH."""

from __future__ import annotations

from typing import Callable

from public_key import ecc, ecdh
from public_key.ecc import Curve, Point, PointLike


def _format_point(point: PointLike) -> str:
    """Return a compact terminal representation of an affine point or infinity."""

    if point is None:
        return "infinity"
    return f"({point.x}, {point.y})"


def _parse_integer(text: str, name: str) -> int:
    """Parse one signed decimal integer with a focused terminal error."""

    if not isinstance(text, str):
        raise TypeError(f"{name} must be text")

    stripped = text.strip()
    if not stripped:
        raise ValueError(f"{name} must not be empty")

    try:
        return int(stripped, 10)
    except ValueError as error:
        raise ValueError(f"{name} must be a decimal integer") from error


def _read_affine_point(input_fn: Callable[[str], str]) -> Point:
    """Read one candidate affine point from separate x/y prompts."""

    x_coordinate = _parse_integer(input_fn("Enter point x-coordinate: "), "Point x")
    y_coordinate = _parse_integer(input_fn("Enter point y-coordinate: "), "Point y")
    return Point(x_coordinate, y_coordinate)


def _require_generator_parameters(curve: Curve) -> tuple[Point, int]:
    """Validate and narrow the menu's required generator parameters."""

    curve.validate()
    generator = curve.generator
    order = curve.order
    if generator is None or order is None:
        raise ValueError("This ECC operation requires generator G and order n")
    return generator, order


def _display_domain_parameters(curve: Curve) -> None:
    """Validate and display the complete educational domain."""

    generator, order = _require_generator_parameters(curve)
    points = curve.enumerate_points()
    discriminant_term = (4 * curve.a**3 + 27 * curve.b**2) % curve.prime
    cofactor = len(points) // order

    print("\nValidated ECC domain parameters:")
    print(f"Curve equation: y^2 = x^3 + {curve.a}x + {curve.b} (mod {curve.prime})")
    print(f"p (field prime): {curve.prime}")
    print(f"a (curve coefficient): {curve.a}")
    print(f"b (curve coefficient): {curve.b}")
    print(f"G (generator): {_format_point(generator)}")
    print(f"n (generator order): {order}")
    print(f"Nonzero discriminant term: {discriminant_term}")
    print(f"nG: {_format_point(curve.multiply(order, generator))}")
    print(f"Total group points: {len(points)}")
    print(f"Cofactor h = #E(F_p)/n: {cofactor}")
    print("Domain validation result: valid")


def _run_point_enumeration(curve: Curve) -> None:
    """Display every point in generator-multiple order.

    ``Curve.enumerate_points()`` still discovers points by scanning canonical
    coordinates. The menu uses the generator cycle because it makes the group
    structure and the meaning of order n visible to the student.
    """

    generator, order = _require_generator_parameters(curve)
    points = curve.enumerate_points()
    cofactor = len(points) // order
    label_width = len(str(order))

    print(f"\nGenerator cycle for G = {_format_point(generator)}:")
    for scalar in range(1, order + 1):
        point = curve.multiply(scalar, generator)
        print(f"{scalar:>{label_width}}G = {_format_point(point)}")

    print(f"\nAffine points: {len(points) - 1}")
    print("Point at infinity: 1")
    print(f"Total points: {len(points)}")
    print(f"Generator order n: {order}")
    print(f"Cofactor h: {cofactor}")

    if order == len(points):
        print(
            "Result: G generates the entire curve group, so 1G through nG "
            "list every point exactly once (with nG = infinity)."
        )
    else:
        print(
            "Result: G generates only a subgroup. The complete coordinate-"
            "sorted point set is shown below."
        )
        for index, point in enumerate(points):
            print(f"Point {index:>{label_width}} = {_format_point(point)}")


def _run_point_inspection(
    input_fn: Callable[[str], str],
    curve: Curve,
) -> None:
    """Validate an entered P(x,y), then display its inverse and order."""

    point = _read_affine_point(input_fn)
    if not curve.contains(point):
        raise ValueError(f"Point {_format_point(point)} is not on the curve")

    inverse = curve.negate(point)
    order = curve.point_order(point)

    print(f"\nP: {_format_point(point)}")
    print("Membership equation result: P is on the curve")
    print(f"-P: {_format_point(inverse)}")
    print(f"P + (-P): {_format_point(curve.add(point, inverse))}")
    print(f"Order of P: {order}")
    print(f"{order}P: {_format_point(curve.multiply(order, point))}")


def _run_key_generation(curve: Curve) -> None:
    """Generate and display one educational ECC private/public key pair."""

    generator, order = _require_generator_parameters(curve)
    private_key = ecdh.generate_private_key(curve)
    public_key = ecdh.public_key(curve, private_key)

    print("\nGenerated educational ECC key pair:")
    print(f"Generator G: {_format_point(generator)}")
    print(f"Generator order n: {order}")
    print(f"Private key d: {private_key}")
    print(f"Public key Q = dG: {_format_point(public_key)}")
    print(f"Subgroup check nQ: {_format_point(curve.multiply(order, public_key))}")
    print("Security note: this 19-element group provides no real security.")


def _read_private_key(
    input_fn: Callable[[str], str],
    prompt: str,
    curve: Curve,
) -> tuple[int, bool]:
    """Read a participant scalar, using secure randomness for an empty input."""

    text = input_fn(prompt)
    if not isinstance(text, str):
        raise TypeError("Private-key input must be text")
    if not text.strip():
        return ecdh.generate_private_key(curve), True

    private_key = _parse_integer(text, "Private key")
    # Public-key derivation later validates the bound. Validate here as well so
    # any error is reported before processing the other participant's values.
    ecdh._validate_private_key(curve, private_key)
    return private_key, False


def _run_ecdh_exchange(
    input_fn: Callable[[str], str],
    curve: Curve,
) -> None:
    """Demonstrate matching Alice/Bob ECDH computations."""

    _, order = _require_generator_parameters(curve)
    print(f"\nEnter private keys in 1..{order - 1}, or press Enter to generate them.")
    alice_private, alice_generated = _read_private_key(
        input_fn,
        "Enter Alice's private key: ",
        curve,
    )
    bob_private, bob_generated = _read_private_key(
        input_fn,
        "Enter Bob's private key: ",
        curve,
    )

    alice_public = ecdh.public_key(curve, alice_private)
    bob_public = ecdh.public_key(curve, bob_private)
    alice_shared = ecdh.shared_point(curve, alice_private, bob_public)
    bob_shared = ecdh.shared_point(curve, bob_private, alice_public)

    if alice_shared != bob_shared:
        raise ArithmeticError("Alice and Bob derived different ECDH points")

    print("\nAlice:")
    print(
        f"Private key dA: {alice_private}"
        f"{' (auto-generated)' if alice_generated else ''}"
    )
    print(f"Public key QA = dA*G: {_format_point(alice_public)}")

    print("\nBob:")
    print(
        f"Private key dB: {bob_private}"
        f"{' (auto-generated)' if bob_generated else ''}"
    )
    print(f"Public key QB = dB*G: {_format_point(bob_public)}")

    print("\nECDH results:")
    print(f"Alice computes dA*QB: {_format_point(alice_shared)}")
    print(f"Bob computes dB*QA: {_format_point(bob_shared)}")
    print("Shared points match: Yes")
    print(f"Shared key demonstration (raw x-coordinate): {alice_shared.x}")
    print("Security note: raw ECDH output is not yet an AES key; real protocols use a KDF.")
    print("Plain ECDH also requires authentication to prevent man-in-the-middle attacks.")


def run_ecc_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run ECC and ECDH operations until returning to the main menu."""

    curve = ecc.DEFAULT_CURVE

    while True:
        print("\nECC / ECDH")
        print("Educational 19-point curve: suitable for inspection, not security.")
        print("1. Show and validate domain parameters")
        print("2. List all curve points")
        print("3. Inspect a point and its order")
        print("4. Generate an ECC key pair")
        print("5. Demonstrate Alice/Bob ECDH")
        print("6. Return to main menu")

        choice = input_fn("Select an operation: ").strip()

        try:
            if choice == "1":
                _display_domain_parameters(curve)
            elif choice == "2":
                _run_point_enumeration(curve)
            elif choice == "3":
                _run_point_inspection(input_fn, curve)
            elif choice == "4":
                _run_key_generation(curve)
            elif choice == "5":
                _run_ecdh_exchange(input_fn, curve)
            elif choice == "6":
                return
            else:
                print("\nInvalid selection. Enter a number from 1 to 6.")
        except (TypeError, ValueError, ArithmeticError) as error:
            print(f"\nError: {error}")
