"""Command-line entry point for the CSE721 cryptography project."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Callable, Sequence

from cli.analysis_menu import run_analysis_menu
from cli.aes_menu import run_aes_menu
from cli.des_menu import run_des_menu
from cli.double_transposition_menu import run_double_transposition_menu
from cli.ecc_menu import run_ecc_menu
from cli.rsa_menu import run_rsa_menu
from cli.substitution_menu import run_substitution_menu


@dataclass(frozen=True)
class Component:
    """A selectable project component and its implementation status."""

    number: str
    name: str
    module: str
    implemented: bool = False


COMPONENTS: tuple[Component, ...] = (
    Component("1", "Substitution Cipher", "classical.substitution", implemented=True),
    Component(
        "2",
        "Double Transposition Cipher",
        "classical.double_transposition",
        implemented=True,
    ),
    Component("3", "DES", "symmetric.des", implemented=True),
    Component("4", "AES-128", "symmetric.aes", implemented=True),
    Component("5", "RSA", "public_key.rsa", implemented=True),
    Component(
        "6",
        "ECC / ECDH",
        "public_key.ecc + public_key.ecdh",
        implemented=True,
    ),
    Component(
        "7",
        "Performance & Security Analysis",
        "analysis.benchmark_suite + analysis.security_analysis",
        implemented=True,
    ),
)


def render_menu() -> str:
    """Return the main menu without performing input/output."""

    lines = ["CSE721 Cryptography Project", ""]
    lines.extend(f"{item.number}. {item.name}" for item in COMPONENTS)
    lines.append("8. Exit")
    return "\n".join(lines)


def list_components() -> str:
    """Return a machine-friendly overview of module ownership and status."""

    lines = []
    for item in COMPONENTS:
        status = "implemented" if item.implemented else "scaffolded"
        lines.append(f"{item.number}: {item.name} [{status}] -> {item.module}")
    return "\n".join(lines)


def interactive_menu(input_fn: Callable[[str], str] = input) -> int:
    """Run main navigation; algorithm submenus are enabled as they are implemented."""

    by_number = {item.number: item for item in COMPONENTS}
    while True:
        print(render_menu())
        choice = input_fn("\nSelect an algorithm: ").strip()
        if choice == "8":
            return 0
        component = by_number.get(choice)
        if component is None:
            print("\nInvalid selection. Enter a number from 1 to 8.\n")
            continue
        if choice == "1":
            run_substitution_menu(input_fn)
            print()
            continue
        if choice == "2":
            run_double_transposition_menu(input_fn)
            print()
            continue
        if choice == "3":
            run_des_menu(input_fn)
            print()
            continue
        if choice == "4":
            run_aes_menu(input_fn)
            print()
            continue
        if choice == "5":
            run_rsa_menu(input_fn)
            print()
            continue
        if choice == "6":
            run_ecc_menu(input_fn)
            print()
            continue
        if choice == "7":
            run_analysis_menu(input_fn)
            print()
            continue
        print(
            f"\n{component.name} is scaffolded in {component.module}; "
            "its interactive submenu is not implemented yet.\n"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list components and implementation status")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        print(list_components())
        return 0
    return interactive_menu()


if __name__ == "__main__":
    raise SystemExit(main())
