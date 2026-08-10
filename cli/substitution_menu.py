"""Interactive terminal menu for the monoalphabetic substitution cipher."""

from __future__ import annotations

from typing import Callable

from classical import frequency_analysis, substitution


# The algorithm may generate as many as 8! candidates, but sending 40,320
# lines to the terminal would make the demonstration unusable. We calculate
# and report the full count while showing only the first part of the result.
MAX_BRUTE_FORCE_DISPLAY = 100


def _display_key_mapping(mapping: dict[str, str]) -> None:
    """Display all 26 substitutions in a compact two-row table."""

    print("\nKey mapping:")
    print("Plain : " + " ".join(mapping.keys()))
    print("Cipher: " + " ".join(mapping.values()))


def _run_encryption(input_fn: Callable[[str], str]) -> None:
    """Collect encryption input and display the required results."""

    plaintext = input_fn("Enter plaintext: ")
    key = input_fn("Enter the 26-letter permutation key: ")

    # Validate once so the normalized key shown to the user is the same key
    # used by both the mapping and the encryption operation.
    normalized_key = substitution.validate_key(key)
    mapping = substitution.build_encryption_mapping(normalized_key)
    ciphertext = substitution.encrypt(plaintext, normalized_key)

    print(f"\nNormalized key: {normalized_key}")
    _display_key_mapping(mapping)
    print(f"\nCiphertext: {ciphertext}")


def _run_decryption(input_fn: Callable[[str], str]) -> None:
    """Collect decryption input and display the recovered plaintext."""

    ciphertext = input_fn("Enter ciphertext: ")
    key = input_fn("Enter the 26-letter permutation key: ")
    plaintext = substitution.decrypt(ciphertext, key)
    print(f"\nDecrypted plaintext: {plaintext}")


def _run_brute_force(input_fn: Callable[[str], str]) -> None:
    """Run the explicitly reduced, educational brute-force demonstration."""

    print(
        "\nThis demonstration exhausts only a small alphabet. "
        "Use 2-6 unique letters for manageable output."
    )
    ciphertext = input_fn("Enter toy ciphertext: ")
    alphabet = input_fn("Enter reduced alphabet (for example ABCD): ")
    candidates = substitution.brute_force_reduced(ciphertext, alphabet)

    shown_candidates = candidates[:MAX_BRUTE_FORCE_DISPLAY]
    print(f"\nTotal candidate keys tested: {len(candidates)}")
    print(f"Displaying: {len(shown_candidates)}")
    for candidate_key, candidate_plaintext in shown_candidates:
        print(f"Key {candidate_key} -> {candidate_plaintext}")

    omitted_count = len(candidates) - len(shown_candidates)
    if omitted_count > 0:
        print(f"... {omitted_count} additional candidates omitted from display.")


def _run_frequency_analysis(input_fn: Callable[[str], str]) -> None:
    """Display counts, percentages, ranks, and a heuristic plaintext preview."""

    ciphertext = input_fn("Enter ciphertext to analyze: ")
    counts = frequency_analysis.letter_counts(ciphertext)
    percentages = frequency_analysis.letter_percentages(ciphertext)
    ranked = frequency_analysis.ranked_letters(ciphertext)
    suggested_mapping = frequency_analysis.suggest_english_mapping(ciphertext)
    preview = frequency_analysis.apply_partial_mapping(ciphertext, suggested_mapping)

    print("\nLetter-frequency table:")
    print("Letter  Count  Percentage")
    for letter in substitution.ALPHABET:
        print(f"{letter:^6}  {counts[letter]:>5}  {percentages[letter]:>9.2f}%")

    observed_ranked = [(letter, count) for letter, count in ranked if count > 0]
    print("\nObserved letters ranked by frequency:")
    if observed_ranked:
        print(", ".join(f"{letter}:{count}" for letter, count in observed_ranked))
    else:
        print("No ASCII letters were found.")

    print("\nSuggested ciphertext -> plaintext mapping:")
    if suggested_mapping:
        print(", ".join(f"{source}->{target}" for source, target in suggested_mapping.items()))
    else:
        print("No mapping can be suggested without ASCII letters.")

    print(f"\nFrequency-based preview: {preview}")
    print("Note: this preview is a heuristic guess, not guaranteed decryption.")


def run_substitution_menu(input_fn: Callable[[str], str] = input) -> None:
    """Run substitution operations until the user returns to the main menu."""

    while True:
        print("\nSubstitution Cipher")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Reduced-alphabet brute force")
        print("4. Frequency analysis")
        print("5. Return to main menu")

        choice = input_fn("Select an operation: ").strip()

        try:
            if choice == "1":
                _run_encryption(input_fn)
            elif choice == "2":
                _run_decryption(input_fn)
            elif choice == "3":
                _run_brute_force(input_fn)
            elif choice == "4":
                _run_frequency_analysis(input_fn)
            elif choice == "5":
                return
            else:
                print("\nInvalid selection. Enter a number from 1 to 5.")
        except (TypeError, ValueError) as error:
            # Invalid user input should return to this submenu instead of
            # terminating the entire project application.
            print(f"\nError: {error}")

