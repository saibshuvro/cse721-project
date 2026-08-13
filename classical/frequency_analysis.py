"""Frequency-analysis template for monoalphabetic substitution.

Frequency analysis does not automatically recover the correct plaintext. It
suggests mappings based on language statistics, which a user can refine using
word patterns and context. This module is intentionally unfinished.
"""

from __future__ import annotations

from string import ascii_letters, ascii_uppercase


# A commonly used approximate frequency order for English. Real frequencies
# depend heavily on message length, topic, names, and writing style.
COMMON_ENGLISH_LETTERS = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


def letter_counts(text: str) -> dict[str, int]:
    # Count ASCII letters case-insensitively, including zero-count letters.
    if type(text) is not str:
        raise TypeError("Input must be a string")
    counts = {letter: 0 for letter in ascii_uppercase}
    for character in text:
        # Validate the original character before case conversion. Unicode
        # uppercasing can expand or normalize characters ("ß" -> "SS",
        # "ı" -> "I"), but this analysis intentionally counts ASCII only.
        if character in ascii_letters:
            counts[character.upper()] += 1
    return counts

    # raise NotImplementedError("TODO(student): count letters A through Z")


def ranked_letters(text: str) -> list[tuple[str, int]]:
    # Return ``(letter, count)`` pairs from most to least frequent.
    counts = letter_counts(text)
    ranked_letters = []
    for letter, count in counts.items():
        ranked_letters.append((letter, count))
    ranked_letters.sort(key=lambda x: (-x[1], x[0]))
    return ranked_letters

    # raise NotImplementedError("TODO(student): rank the frequency table")


def letter_percentages(text: str) -> dict[str, float]:
    # Return each letter's percentage among ASCII letters in ``text``.
    counts = letter_counts(text)
    total = sum(counts.values())
    percentages = {}
    for letter, count in counts.items():
        if total == 0:
            percentages[letter] = 0.0
        else:
            percentages[letter] = (count / total) * 100
    return percentages

    # raise NotImplementedError("TODO(student): calculate letter percentages")


def suggest_english_mapping(ciphertext: str) -> dict[str, str]:
    """Suggest a ciphertext-to-plaintext mapping using frequency ranks.

    Suppose X is the most frequent ciphertext letter. The simplest heuristic
    guesses X -> E because E is commonly the most frequent English letter. The
    second-ranked ciphertext letter is guessed to represent T, and so on.

    This is only an initial guess. Never label it as guaranteed plaintext.
    Short ciphertexts in particular may produce very poor suggestions.
    """
    ranked_ciphertext_letters = ranked_letters(ciphertext)
    mapping = {}

    # ranked_letters() always contains A-Z, including letters with a count of
    # zero. Unseen letters provide no evidence, so they must not be included in
    # the suggested mapping.
    english_rank_index = 0
    for ciphertext_letter, count in ranked_ciphertext_letters:
        if count == 0:
            continue

        guessed_plaintext_letter = COMMON_ENGLISH_LETTERS[english_rank_index]
        mapping[ciphertext_letter] = guessed_plaintext_letter
        english_rank_index += 1

    return mapping


def apply_partial_mapping(
    ciphertext: str,
    mapping: dict[str, str],
    unknown_marker: str = "_",
) -> str:
    """Preview a guessed ciphertext-to-plaintext mapping.

    Keeping this separate lets the user edit the suggested mapping and preview
    the effect without changing the actual encryption key.
    """
    if type(ciphertext) is not str:
        raise TypeError("Ciphertext must be a string")
    if type(mapping) is not dict:
        raise TypeError("Mapping must be a dictionary")
    if type(unknown_marker) is not str:
        raise TypeError("Unknown marker must be a string")
    if len(unknown_marker) != 1:
        raise ValueError("Unknown marker must contain exactly one character")

    normalized_mapping: dict[str, str] = {}
    for ciphertext_letter, plaintext_letter in mapping.items():
        if type(ciphertext_letter) is not str or type(plaintext_letter) is not str:
            raise TypeError("Mapping keys and values must be strings")

        if (
            len(ciphertext_letter) != 1
            or ciphertext_letter not in ascii_letters
            or len(plaintext_letter) != 1
            or plaintext_letter not in ascii_letters
        ):
            raise ValueError("Mapping keys and values must be single ASCII letters A-Z")

        normalized_ciphertext_letter = ciphertext_letter.upper()
        normalized_plaintext_letter = plaintext_letter.upper()

        # A partial substitution must still be one-to-one. Two ciphertext
        # letters cannot represent the same plaintext letter.
        if normalized_plaintext_letter in normalized_mapping.values():
            raise ValueError("Mapping values must not contain duplicate letters")
        if normalized_ciphertext_letter in normalized_mapping:
            raise ValueError("Mapping keys must not contain duplicate letters")

        normalized_mapping[normalized_ciphertext_letter] = normalized_plaintext_letter

    preview_characters: list[str] = []
    for character in ciphertext:
        # Non-ASCII letters and all non-letter characters are outside this
        # cipher's alphabet, so they are copied unchanged.
        if character not in ascii_letters:
            preview_characters.append(character)
            continue

        uppercase_character = character.upper()

        if uppercase_character not in normalized_mapping:
            preview_characters.append(unknown_marker)
            continue

        translated_character = normalized_mapping[uppercase_character]
        if character.islower():
            translated_character = translated_character.lower()
        preview_characters.append(translated_character)

    return "".join(preview_characters)
