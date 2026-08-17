"""Staged tests for the guided AES-128 implementation.

Primary reference: NIST FIPS 197-upd1. The block-mode vector is from NIST
SP 800-38A / the official NIST AES-128 ECB example values.
"""

from __future__ import annotations

import unittest

from symmetric import aes
from symmetric.aes_tables import (
    INV_MIX_COLUMNS_MATRIX,
    INV_S_BOX,
    MIX_COLUMNS_MATRIX,
    ROUND_CONSTANTS,
    S_BOX,
)


class AESFixedTableTests(unittest.TestCase):
    """Protect the supplied FIPS constants from transcription/editing errors."""

    def test_sboxes_are_complete_inverse_byte_permutations(self) -> None:
        self.assertEqual(len(S_BOX), 256)
        self.assertEqual(len(INV_S_BOX), 256)
        self.assertEqual(set(S_BOX), set(range(256)))
        self.assertEqual(set(INV_S_BOX), set(range(256)))
        for value in range(256):
            self.assertEqual(INV_S_BOX[S_BOX[value]], value)

    def test_fips_sbox_examples(self) -> None:
        self.assertEqual(S_BOX[0x00], 0x63)
        self.assertEqual(S_BOX[0x53], 0xED)
        self.assertEqual(INV_S_BOX[0xED], 0x53)

    def test_round_constants_and_mix_matrices(self) -> None:
        self.assertEqual(
            ROUND_CONSTANTS,
            (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36),
        )
        self.assertEqual(MIX_COLUMNS_MATRIX[0], (0x02, 0x03, 0x01, 0x01))
        self.assertEqual(INV_MIX_COLUMNS_MATRIX[0], (0x0E, 0x0B, 0x0D, 0x09))


class AESStateTests(unittest.TestCase):
    def test_state_uses_column_major_fips_layout(self) -> None:
        block = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        state = aes._bytes_to_state(block)
        self.assertEqual(
            state,
            (
                (0x00, 0x44, 0x88, 0xCC),
                (0x11, 0x55, 0x99, 0xDD),
                (0x22, 0x66, 0xAA, 0xEE),
                (0x33, 0x77, 0xBB, 0xFF),
            ),
        )
        self.assertEqual(aes._state_to_bytes(state), block)

        with self.assertRaises(TypeError):
            aes._bytes_to_state(bytearray(block))
        with self.assertRaises(ValueError):
            aes._bytes_to_state(block[:-1])

    def test_invalid_state_shapes_and_byte_values_are_rejected(self) -> None:
        with self.assertRaises((TypeError, ValueError)):
            aes._validate_state(((0, 1), (2, 3)))
        with self.assertRaises((TypeError, ValueError)):
            aes._validate_state(tuple((0, 0, 0, 256) for _ in range(4)))
        with self.assertRaises(TypeError):
            aes._validate_state([[0, 0, 0, 0] for _ in range(4)])
        with self.assertRaises(TypeError):
            aes._validate_state(tuple((0, 0, 0, False) for _ in range(4)))

        valid_state = tuple((0, 1, 254, 255) for _ in range(4))
        self.assertIs(aes._validate_state(valid_state), valid_state)


class AESKeyExpansionTests(unittest.TestCase):
    def test_generated_key_is_exactly_128_bits(self) -> None:
        key = aes.generate_key()
        self.assertIs(type(key), bytes)
        self.assertEqual(len(key), aes.KEY_SIZE)

    def test_xor_words_combines_corresponding_bytes(self) -> None:
        self.assertEqual(
            aes._xor_words((0x2B, 0x7E, 0x15, 0x16), (0x8B, 0x84, 0xEB, 0x01)),
            (0xA0, 0xFA, 0xFE, 0x17),
        )
        with self.assertRaises(TypeError):
            aes._xor_words([0, 0, 0, 0], (0, 0, 0, 0))
        with self.assertRaises(ValueError):
            aes._xor_words((0, 0, 0), (0, 0, 0, 0))
        with self.assertRaises(ValueError):
            aes._xor_words((0, 0, 0, 256), (0, 0, 0, 0))

    def test_rot_word_sub_word_and_xor_word(self) -> None:
        word = (0x09, 0xCF, 0x4F, 0x3C)
        rotated = aes._rot_word(word)
        substituted = aes._sub_word(rotated)
        self.assertEqual(rotated, (0xCF, 0x4F, 0x3C, 0x09))
        self.assertEqual(substituted, (0x8A, 0x84, 0xEB, 0x01))
        self.assertEqual(
            aes._xor_words((0x2B, 0x7E, 0x15, 0x16), (0x8B, 0x84, 0xEB, 0x01)),
            (0xA0, 0xFA, 0xFE, 0x17),
        )

    def test_fips_aes128_key_expansion(self) -> None:
        # FIPS 197-upd1 Appendix A.1.
        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        round_keys = aes.expand_key(key)
        self.assertEqual(len(round_keys), 11)
        self.assertEqual(round_keys[0], key)
        self.assertEqual(
            round_keys[1],
            bytes.fromhex("A0FAFE1788542CB123A339392A6C7605"),
        )
        self.assertEqual(
            round_keys[-1],
            bytes.fromhex("D014F9A8C9EE2589E13F0CC8B6630CA6"),
        )
        with self.assertRaises(TypeError):
            aes.expand_key("not bytes")
        with self.assertRaises(ValueError):
            aes.expand_key(key[:-1])


class AESTransformationTests(unittest.TestCase):
    def test_sub_bytes_and_inverse_restore_state(self) -> None:
        state = aes._bytes_to_state(
            bytes.fromhex("00102030405060708090A0B0C0D0E0F0")
        )
        substituted = aes._sub_bytes(state)
        self.assertEqual(
            aes._state_to_bytes(substituted),
            bytes.fromhex("63CAB7040953D051CD60E0E7BA70E18C"),
        )
        self.assertEqual(aes._inv_sub_bytes(substituted), state)

    def test_shift_rows_matches_fips_intermediate_state(self) -> None:
        state = aes._bytes_to_state(
            bytes.fromhex("63CAB7040953D051CD60E0E7BA70E18C")
        )
        shifted = aes._shift_rows(state)
        self.assertEqual(
            aes._state_to_bytes(shifted),
            bytes.fromhex("6353E08C0960E104CD70B751BACAD0E7"),
        )
        self.assertEqual(aes._inv_shift_rows(shifted), state)

    def test_xtime_and_general_field_multiplication(self) -> None:
        # FIPS 197 finite-field examples.
        self.assertEqual(aes._xtime(0x57), 0xAE)
        self.assertEqual(aes._xtime(0xAE), 0x47)
        self.assertEqual(aes._gf_multiply(0x57, 0x13), 0xFE)
        self.assertEqual(aes._gf_multiply(0x57, 0x00), 0x00)
        self.assertEqual(aes._gf_multiply(0x57, 0x01), 0x57)
        with self.assertRaises(TypeError):
            aes._xtime(True)
        with self.assertRaises(ValueError):
            aes._gf_multiply(0x100, 0x02)

    def test_mix_columns_matches_fips_intermediate_state(self) -> None:
        state = aes._bytes_to_state(
            bytes.fromhex("6353E08C0960E104CD70B751BACAD0E7")
        )
        mixed = aes._mix_columns(state)
        self.assertEqual(
            aes._state_to_bytes(mixed),
            bytes.fromhex("5F72641557F5BC92F7BE3B291DB9F91A"),
        )

        self.assertEqual(
            aes._mix_single_column(
                (0xDB, 0x13, 0x53, 0x45),
                MIX_COLUMNS_MATRIX,
            ),
            (0x8E, 0x4D, 0xA1, 0xBC),
        )

    def test_inv_mix_columns_restores_state(self) -> None:
        state = aes._bytes_to_state(
            bytes.fromhex("6353E08C0960E104CD70B751BACAD0E7")
        )
        mixed = aes._mix_columns(state)
        self.assertEqual(aes._inv_mix_columns(mixed), state)

    def test_add_round_key_matches_fips_intermediate_state(self) -> None:
        state = aes._bytes_to_state(
            bytes.fromhex("5F72641557F5BC92F7BE3B291DB9F91A")
        )
        round_key = bytes.fromhex("D6AA74FDD2AF72FADAA678F1D6AB76FE")
        result = aes._add_round_key(state, round_key)
        self.assertEqual(
            aes._state_to_bytes(result),
            bytes.fromhex("89D810E8855ACE682D1843D8CB128FE4"),
        )
        self.assertEqual(aes._add_round_key(result, round_key), state)


class AESBlockTests(unittest.TestCase):
    def test_fips_aes128_known_answer_and_trace(self) -> None:
        # FIPS 197 AES-128 example vector.
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        ciphertext, trace = aes.encrypt_block(plaintext, key)
        self.assertEqual(ciphertext, bytes.fromhex("69C4E0D86A7B0430D8CDB78070B4C55A"))
        self.assertEqual(len(trace.round_keys), 11)
        self.assertEqual(trace.operation, "encrypt")
        self.assertEqual(trace.output, ciphertext)
        self.assertEqual(len(trace.stages), 40)
        self.assertEqual(
            (trace.stages[0].round_number, trace.stages[0].transformation),
            (0, "AddRoundKey"),
        )
        self.assertEqual(trace.stages[-1].state, ciphertext)
        self.assertEqual(
            [
                stage.round_key
                for stage in trace.stages
                if stage.round_key is not None
            ],
            list(trace.round_keys),
        )
        self.assertNotIn(
            (10, "MixColumns"),
            {(stage.round_number, stage.transformation) for stage in trace.stages},
        )

    def test_fips_aes128_known_answer_decrypts(self) -> None:
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        ciphertext = bytes.fromhex("69C4E0D86A7B0430D8CDB78070B4C55A")
        plaintext, trace = aes.decrypt_block(ciphertext, key)
        self.assertEqual(plaintext, bytes.fromhex("00112233445566778899AABBCCDDEEFF"))
        self.assertEqual(trace.operation, "decrypt")
        self.assertEqual(trace.round_keys[0], key)
        self.assertEqual(trace.output, plaintext)
        self.assertEqual(len(trace.stages), 40)
        self.assertEqual(
            (trace.stages[0].round_number, trace.stages[0].transformation),
            (10, "AddRoundKey"),
        )
        self.assertEqual(
            [
                stage.round_key
                for stage in trace.stages
                if stage.round_key is not None
            ],
            list(reversed(trace.round_keys)),
        )
        self.assertNotIn(
            (0, "InvMixColumns"),
            {(stage.round_number, stage.transformation) for stage in trace.stages},
        )

    def test_nist_sp800_38a_ecb_block_vector(self) -> None:
        key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
        plaintext = bytes.fromhex("6BC1BEE22E409F96E93D7E117393172A")
        expected = bytes.fromhex("3AD77BB40D7A3660A89ECAF32466EF97")
        ciphertext, _ = aes.encrypt_block(plaintext, key)
        recovered, _ = aes.decrypt_block(ciphertext, key)
        self.assertEqual(ciphertext, expected)
        self.assertEqual(recovered, plaintext)


class AESPaddingAndECBTests(unittest.TestCase):
    def test_multiblock_utf8_round_trip(self) -> None:
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        plaintext = "AES handles UTF-8: বাংলা".encode()
        ciphertext, encryption_traces = aes.encrypt_ecb(plaintext, key)
        recovered, decryption_traces = aes.decrypt_ecb(ciphertext, key)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(len(ciphertext) % aes.BLOCK_SIZE, 0)
        self.assertEqual(len(encryption_traces), len(decryption_traces))

    def test_ecb_always_adds_pkcs7_padding(self) -> None:
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

        empty_ciphertext, empty_traces = aes.encrypt_ecb(b"", key)
        self.assertEqual(len(empty_ciphertext), aes.BLOCK_SIZE)
        self.assertEqual(len(empty_traces), 1)
        self.assertEqual(aes.decrypt_ecb(empty_ciphertext, key)[0], b"")

        aligned_plaintext = bytes(aes.BLOCK_SIZE)
        aligned_ciphertext, aligned_traces = aes.encrypt_ecb(
            aligned_plaintext,
            key,
        )
        self.assertEqual(len(aligned_ciphertext), 2 * aes.BLOCK_SIZE)
        self.assertEqual(len(aligned_traces), 2)
        self.assertEqual(
            aes.decrypt_ecb(aligned_ciphertext, key)[0],
            aligned_plaintext,
        )

    def test_ecb_validates_inputs_and_padding(self) -> None:
        key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")

        with self.assertRaises(TypeError):
            aes.encrypt_ecb("plaintext", key)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            aes.encrypt_ecb(b"plaintext", b"short")
        with self.assertRaises(TypeError):
            aes.decrypt_ecb("ciphertext", key)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            aes.decrypt_ecb(b"", key)
        with self.assertRaises(ValueError):
            aes.decrypt_ecb(b"not aligned", key)

        # Build a genuine AES ciphertext whose decrypted final block has
        # malformed padding: 0x02 claims two bytes, but the previous byte is A.
        malformed_block = b"A" * 15 + b"\x02"
        malformed_ciphertext, _ = aes.encrypt_block(malformed_block, key)
        with self.assertRaises(ValueError):
            aes.decrypt_ecb(malformed_ciphertext, key)


if __name__ == "__main__":
    unittest.main()
