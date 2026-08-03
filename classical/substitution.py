"""General monoalphabetic substitution cipher guided template.

This file is intentionally NOT a completed solution. Fill in every section
marked ``TODO(student)`` in the order shown in
``docs/substitution-cipher-guide.md``.

Key format
----------
The key is a 26-letter permutation. Its position determines which plaintext
letter it replaces:

    Plain alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ
    Example key:    QWERTYUIOPASDFGHJKLZXCVBNM

Therefore A maps to Q, B maps to W, C maps to E, ..., and Z maps to M.

Project policy
--------------
* Keys are accepted in either case and normalized to uppercase.
* A valid key contains every ASCII letter A-Z exactly once.
* Letter case is preserved during encryption and decryption.
* Spaces, digits, punctuation, and non-ASCII letters remain unchanged.
* Core functions return values; they never call ``input`` or ``print``.

Keeping input/output outside this module makes the cipher independently
testable and reusable from either a terminal menu or a future web page.
"""

from __future__ import annotations

from itertools import permutations
from string import ascii_uppercase


ALPHABET = ascii_uppercase


def validate_key(key: str) -> str:
    # Return a normalized 26-letter permutation or raise an exception.
    if type(key) is not str:
        raise TypeError("Key must be a string")
    key = key.upper()
    if len(key) != 26:
        raise ValueError("Key must be exactly 26 letters long")
    if set(key) != set(ALPHABET):
        raise ValueError("Key must contain each letter A-Z exactly once")
    return key

    # raise NotImplementedError("TODO(student): validate the permutation key")


def build_encryption_mapping(key: str) -> dict[str, str]:
    # Return the plaintext-to-ciphertext mapping for all 26 letters.
    key = validate_key(key)
    mapping = {}
    for plain_letter, cipher_letter in zip(ALPHABET, key):
        mapping[plain_letter] = cipher_letter
    return mapping

    # raise NotImplementedError("TODO(student): build the encryption mapping")


def build_decryption_mapping(key: str) -> dict[str, str]:
    # Return the inverse ciphertext-to-plaintext mapping.
    encryption_mapping = build_encryption_mapping(key)
    decryption_mapping = {}
    for key, value in encryption_mapping.items():
        decryption_mapping[value] = key
    return decryption_mapping

    # raise NotImplementedError("TODO(student): invert the encryption mapping")


def _translate_character(character: str, mapping: dict[str, str]) -> str:
    # Translate one ASCII letter with ``mapping`` while preserving case.
    character_upper = character.upper()
    if character_upper not in ALPHABET:
        return character
    translated_char = mapping[character_upper]
    if character.islower():
        return translated_char.lower()
    else:
        return translated_char

    # raise NotImplementedError("TODO(student): translate one character")


def encrypt(plaintext: str, key: str) -> str:
    # Encrypt text using a general monoalphabetic substitution key.
    if type(plaintext) is not str:
        raise TypeError("Plaintext must be a string")
    mapping = build_encryption_mapping(key)
    ciphertext = ""
    for char in plaintext:
        translated_char = _translate_character(char, mapping)
        ciphertext += translated_char
    return ciphertext

    # raise NotImplementedError("TODO(student): implement substitution encryption")


def decrypt(ciphertext: str, key: str) -> str:
    # Decrypt text by applying the inverse of the substitution key.
    if type(ciphertext) is not str:
        raise TypeError("Ciphertext must be a string")
    mapping = build_decryption_mapping(key)
    plaintext = ""
    for char in ciphertext:
        translated_char = _translate_character(char, mapping)
        plaintext += translated_char
    return plaintext

    # raise NotImplementedError("TODO(student): implement substitution decryption")


def validate_reduced_alphabet(alphabet: str, maximum_size: int = 8) -> str:
    """Validate a small alphabet used only for the brute-force demonstration.

    Full brute force is impossible for a normal 26-letter substitution because
    it has 26! possible keys. A small alphabet makes exhaustive search visible
    and measurable without falsely claiming to search the real key space.

    TODO(student):
        1. Require ``alphabet`` to be a string and normalize it to uppercase.
        2. Require at least two unique ASCII letters.
        3. Reject duplicates and non-ASCII letters.
        4. Reject an alphabet longer than ``maximum_size``. With the default
           cap, the largest search has 8! = 40,320 keys.
        5. Return the normalized alphabet.
    """
    if type(alphabet) is not str:
        raise TypeError("Alphabet must be a string")
    alphabet = alphabet.upper()
    if len(set(alphabet)) < 2:
        raise ValueError("Alphabet must contain at least two unique letters")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("Alphabet must not contain duplicate letters")
    if len(alphabet) > maximum_size:
        raise ValueError(f"Alphabet must not exceed {maximum_size} letters")
    for letter in alphabet:
        if letter not in ALPHABET:
            raise ValueError("Alphabet must contain only ASCII letters A-Z")
    return alphabet

    # raise NotImplementedError("TODO(student): validate the toy alphabet")


def brute_force_reduced(
    ciphertext: str,
    alphabet: str,
) -> list[tuple[str, str]]:
    """Try every permutation of a small alphabet.

    Return ``(candidate_key, candidate_plaintext)`` pairs. For example, if the
    toy alphabet is ``ABC``, its six candidate keys are the permutations of
    those three letters. Text for this demonstration should contain only those
    letters plus characters that are intentionally left unchanged.

    TODO(student):
        1. Validate the reduced alphabet.
        2. Use ``itertools.permutations`` from the Python standard library to
           generate every candidate encryption key for that alphabet.
        3. For each candidate, pair plaintext alphabet letters with candidate
           ciphertext letters, then invert that mapping for decryption.
        4. Decrypt the supplied ciphertext under that candidate mapping.
        5. Append ``(candidate_key, candidate_plaintext)`` and return all
           candidates.

    This function is a demonstration of factorial growth, not an attack that
    can exhaust the real 26-letter key space. State that clearly in the UI and
    final report.
    """
    if type(ciphertext) is not str:
        raise TypeError("Ciphertext must be a string")
    if type(alphabet) is not str:
        raise TypeError("Alphabet must be a string")
    alphabet = validate_reduced_alphabet(alphabet)

    candidates: list[tuple[str, str]] = []

    # A candidate key has the same positional meaning as the full cipher key.
    # For alphabet="ABC" and candidate_key="BCA", encryption maps A->B,
    # B->C, and C->A.
    for candidate_tuple in permutations(alphabet):
        candidate_key = "".join(candidate_tuple)

        encryption_mapping = dict(zip(alphabet, candidate_key))
        decryption_mapping = {
            cipher_letter: plain_letter
            for plain_letter, cipher_letter in encryption_mapping.items()
        }

        plaintext_characters: list[str] = []
        for character in ciphertext:
            uppercase_character = character.upper()

            # Characters outside the toy alphabet are not encrypted by this
            # reduced demonstration, so preserve them exactly as supplied.
            if uppercase_character not in decryption_mapping:
                plaintext_characters.append(character)
                continue

            translated_character = decryption_mapping[uppercase_character]
            if character.islower():
                translated_character = translated_character.lower()
            plaintext_characters.append(translated_character)

        candidate_plaintext = "".join(plaintext_characters)
        candidates.append((candidate_key, candidate_plaintext))

    return candidates
