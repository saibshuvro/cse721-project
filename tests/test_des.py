"""Tests to enable gradually while implementing the guided DES template.

Primary vectors are from NIST SP 800-17, Appendix A and Appendix B Table 1.
"""

from __future__ import annotations

import unittest

from common.padding import pkcs7_pad, pkcs7_unpad
from symmetric import des
from symmetric.des_tables import (
    EXPANSION_PERMUTATION,
    FINAL_PERMUTATION,
    INITIAL_PERMUTATION,
    PERMUTED_CHOICE_1,
    PERMUTED_CHOICE_2,
    P_PERMUTATION,
    ROUND_SHIFTS,
    S_BOXES,
)


class DESFixedTableTests(unittest.TestCase):
    """Catch accidental edits or incomplete transcription of standard tables."""

    def test_permutation_table_lengths_and_ranges(self) -> None:
        expected = (
            (INITIAL_PERMUTATION, 64, 64),
            (FINAL_PERMUTATION, 64, 64),
            (EXPANSION_PERMUTATION, 48, 32),
            (P_PERMUTATION, 32, 32),
            (PERMUTED_CHOICE_1, 56, 64),
            (PERMUTED_CHOICE_2, 48, 56),
        )
        for table, length, input_width in expected:
            with self.subTest(length=length, input_width=input_width):
                self.assertEqual(len(table), length)
                self.assertTrue(all(1 <= position <= input_width for position in table))

    def test_sbox_shapes_and_rows(self) -> None:
        self.assertEqual(len(S_BOXES), 8)
        for box in S_BOXES:
            self.assertEqual(len(box), 4)
            for row in box:
                self.assertEqual(len(row), 16)
                self.assertEqual(set(row), set(range(16)))

    def test_shift_schedule(self) -> None:
        self.assertEqual(len(ROUND_SHIFTS), 16)
        self.assertEqual(ROUND_SHIFTS, (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1))


class DESBitFoundationTests(unittest.TestCase):
    def test_initial_and_final_permutations_are_inverses(self) -> None:
        block = 0x0123456789ABCDEF
        after_ip = des._permute(block, 64, INITIAL_PERMUTATION)
        self.assertEqual(after_ip, 0xCC00CCFFF0AAF0AA)
        self.assertEqual(des._permute(after_ip, 64, FINAL_PERMUTATION), block)

    def test_28_bit_rotation_wraps(self) -> None:
        self.assertEqual(des._rotate_left_28(0x8000001, 1), 0x0000003)

    def test_bit_helpers_validate_inputs(self) -> None:
        with self.assertRaises(TypeError):
            des._permute("0", 1, (1,))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des._permute(0, 0, (1,))
        with self.assertRaises(ValueError):
            des._permute(0, 1, (2,))
        with self.assertRaises(TypeError):
            des._rotate_left_28(0, 1.5)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des._rotate_left_28(1 << 28, 1)


class DESKeyTests(unittest.TestCase):
    def test_odd_parity_can_be_set_and_checked(self) -> None:
        key = des.set_odd_parity(bytes(8))
        self.assertEqual(key, bytes.fromhex("0101010101010101"))
        self.assertTrue(des.has_odd_parity(key))

    def test_standard_key_schedule_endpoints(self) -> None:
        # Common worked example derived directly from the FIPS PC-1/PC-2 tables.
        keys = des.expand_key(bytes.fromhex("133457799BBCDFF1"))
        self.assertEqual(len(keys), 16)
        self.assertEqual(keys[0], 0x1B02EFFC7072)
        self.assertEqual(keys[-1], 0xCB3D8B0E17F5)
        self.assertTrue(all(0 <= key < (1 << 48) for key in keys))

        schedule = des.build_key_schedule(bytes.fromhex("133457799BBCDFF1"))
        self.assertEqual(
            tuple(round_state.round_number for round_state in schedule),
            tuple(range(1, 17)),
        )
        self.assertEqual(
            tuple(round_state.shift for round_state in schedule),
            ROUND_SHIFTS,
        )
        self.assertTrue(
            all(
                0 <= round_state.left_half < (1 << 28)
                and 0 <= round_state.right_half < (1 << 28)
                for round_state in schedule
            )
        )

    def test_generated_key_has_parity_and_is_not_weak(self) -> None:
        key = des.generate_key()
        self.assertEqual(len(key), 8)
        self.assertTrue(des.has_odd_parity(key))
        self.assertFalse(des.is_weak_key(key))


class DESBlockTests(unittest.TestCase):
    def test_fips_s1_example(self) -> None:
        # FIPS 46-3 demonstrates that S1(011011) = 0101. Put that chunk in
        # the leftmost S1 position and fill the remaining chunks with zero.
        value = int("011011" + "000000" * 7, 2)
        output = des._sbox_substitute(value)
        self.assertEqual(output >> 28, 0b0101)

    def test_s1_uses_both_outer_bits_for_all_rows(self) -> None:
        # Keep the S1 column at zero while selecting rows 0, 1, 2, and 3.
        # S1[row][0] is respectively 14, 0, 4, and 15.
        chunks_and_expected = (
            (0b000000, 14),  # outer bits 00 -> row 0
            (0b000001, 0),   # outer bits 01 -> row 1
            (0b100000, 4),   # outer bits 10 -> row 2
            (0b100001, 15),  # outer bits 11 -> row 3
        )
        for chunk, expected in chunks_and_expected:
            with self.subTest(chunk=f"{chunk:06b}"):
                value = chunk << 42
                self.assertEqual(des._sbox_substitute(value) >> 28, expected)

    def test_sbox_input_must_be_a_48_bit_integer(self) -> None:
        with self.assertRaises(TypeError):
            des._sbox_substitute("0")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des._sbox_substitute(-1)
        with self.assertRaises(ValueError):
            des._sbox_substitute(1 << 48)

    def test_feistel_standard_first_round_values(self) -> None:
        # First round of the common DES example using plaintext
        # 0123456789ABCDEF and key 133457799BBCDFF1.
        result = des._feistel(0xF0AAF0AA, 0x1B02EFFC7072)
        self.assertEqual(
            result,
            (
                0x7A15557A1555,  # E(R0)
                0x6117BA866527,  # E(R0) XOR K1
                0x5C82B597,      # S1..S8 output
                0x234AA9BB,      # P permutation / f(R0, K1)
            ),
        )

    def test_feistel_validates_operand_widths(self) -> None:
        with self.assertRaises(TypeError):
            des._feistel("0", 0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des._feistel(1 << 32, 0)
        with self.assertRaises(TypeError):
            des._feistel(0, b"key")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des._feistel(0, 1 << 48)

    def test_process_block_matches_nist_known_answer(self) -> None:
        key = bytes.fromhex("0101010101010101")
        plaintext = bytes.fromhex("8000000000000000")
        expected_ciphertext = bytes.fromhex("95F8A5E5DD31D900")

        ciphertext, encryption_trace = des._process_block(
            plaintext,
            key,
            "encrypt",
        )
        recovered, decryption_trace = des._process_block(
            ciphertext,
            key,
            "decrypt",
        )

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(len(encryption_trace.rounds), 16)
        self.assertEqual(
            encryption_trace.preoutput,
            (encryption_trace.rounds[-1].right_output << 32)
            | encryption_trace.rounds[-1].left_output,
        )
        self.assertEqual(
            decryption_trace.rounds[0].subkey,
            decryption_trace.round_keys[-1],
        )
        self.assertEqual(
            decryption_trace.rounds[-1].subkey,
            decryption_trace.round_keys[0],
        )

    def test_process_block_validates_inputs(self) -> None:
        key = bytes.fromhex("0101010101010101")
        with self.assertRaises(TypeError):
            des._process_block("12345678", key, "encrypt")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des._process_block(b"short", key, "encrypt")
        with self.assertRaises(ValueError):
            des._process_block(bytes(8), key, "invalid")

    def test_nist_variable_plaintext_known_answer(self) -> None:
        # NIST SP 800-17, Appendix B, Table 1, round 0.
        key = bytes.fromhex("0101010101010101")
        plaintext = bytes.fromhex("8000000000000000")
        expected = bytes.fromhex("95F8A5E5DD31D900")
        ciphertext, trace = des.encrypt_block(plaintext, key)
        self.assertEqual(ciphertext, expected)
        self.assertEqual(len(trace.round_keys), 16)
        self.assertEqual(len(trace.rounds), 16)
        self.assertEqual(trace.preoutput, (trace.rounds[-1].right_output << 32) | trace.rounds[-1].left_output)

    def test_nist_known_answer_decrypts(self) -> None:
        key = bytes.fromhex("0101010101010101")
        ciphertext = bytes.fromhex("95F8A5E5DD31D900")
        plaintext, trace = des.decrypt_block(ciphertext, key)
        self.assertEqual(plaintext, bytes.fromhex("8000000000000000"))
        self.assertEqual(trace.rounds[0].subkey, trace.round_keys[-1])
        self.assertEqual(trace.rounds[-1].subkey, trace.round_keys[0])

    def test_nist_sample_round_output_vector(self) -> None:
        # NIST SP 800-17, Appendix A.
        key = bytes.fromhex("10316E028C8F3B4A")
        ciphertext, trace = des.encrypt_block(bytes(8), key)
        self.assertEqual(ciphertext, bytes.fromhex("82DCBAFBDEAB6602"))
        self.assertEqual(trace.rounds[0].left_output, 0x00000000)
        self.assertEqual(trace.rounds[0].right_output, 0x47092B5B)


class DESPaddingAndECBTests(unittest.TestCase):
    def test_pkcs7_pad_adds_required_bytes(self) -> None:
        self.assertEqual(pkcs7_pad(b"HELLO", 8), b"HELLO\x03\x03\x03")

        # An aligned message still needs a complete padding block. Otherwise
        # unpadding could not distinguish message bytes from absent padding.
        self.assertEqual(pkcs7_pad(b"12345678", 8), b"12345678" + b"\x08" * 8)
        self.assertEqual(pkcs7_pad(b"", 8), b"\x08" * 8)

    def test_pkcs7_pad_validates_arguments(self) -> None:
        with self.assertRaises(TypeError):
            pkcs7_pad("HELLO", 8)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            pkcs7_pad(b"HELLO", True)
        with self.assertRaises(ValueError):
            pkcs7_pad(b"HELLO", 0)
        with self.assertRaises(ValueError):
            pkcs7_pad(b"HELLO", 256)

    def test_pkcs7_padding_is_strict_and_reversible(self) -> None:
        self.assertEqual(pkcs7_pad(b"HELLO", 8), b"HELLO\x03\x03\x03")
        self.assertEqual(pkcs7_unpad(b"HELLO\x03\x03\x03", 8), b"HELLO")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"HELLO\x03\x02\x03", 8)

    def test_pkcs7_unpad_validates_arguments_and_structure(self) -> None:
        with self.assertRaises(TypeError):
            pkcs7_unpad("12345678", 8)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            pkcs7_unpad(bytes(8), True)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(8), 0)
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"", 8)
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"unaligned", 8)
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(8), 8)  # Last byte says padding length zero.
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"1234567\x09", 8)  # Padding exceeds block size.

    def test_pkcs7_unpad_removes_a_complete_padding_block(self) -> None:
        padded = b"12345678" + b"\x08" * 8
        self.assertEqual(pkcs7_unpad(padded, 8), b"12345678")

    def test_encrypt_ecb_pads_and_encrypts_every_block(self) -> None:
        key = bytes.fromhex("0101010101010101")
        plaintext = bytes.fromhex("8000000000000000")

        ciphertext, traces = des.encrypt_ecb(plaintext, key)

        # The already aligned plaintext receives a complete padding block.
        self.assertEqual(len(ciphertext), 16)
        self.assertEqual(len(traces), 2)
        self.assertEqual(ciphertext[:8], bytes.fromhex("95F8A5E5DD31D900"))
        self.assertTrue(all(trace.operation == "encrypt" for trace in traces))

    def test_encrypt_ecb_accepts_empty_plaintext(self) -> None:
        key = bytes.fromhex("133457799BBCDFF1")
        ciphertext, traces = des.encrypt_ecb(b"", key)
        self.assertEqual(len(ciphertext), des.BLOCK_SIZE)
        self.assertEqual(len(traces), 1)

    def test_encrypt_ecb_validates_inputs(self) -> None:
        key = bytes.fromhex("133457799BBCDFF1")
        with self.assertRaises(TypeError):
            des.encrypt_ecb("plaintext", key)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des.encrypt_ecb(b"plaintext", b"short")

    def test_multiblock_ecb_round_trip(self) -> None:
        key = bytes.fromhex("133457799BBCDFF1")
        plaintext = "DES handles UTF-8: বাংলা".encode()
        ciphertext, encryption_traces = des.encrypt_ecb(plaintext, key)
        recovered, decryption_traces = des.decrypt_ecb(ciphertext, key)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(len(ciphertext) % des.BLOCK_SIZE, 0)
        self.assertEqual(len(encryption_traces), len(decryption_traces))

    def test_decrypt_ecb_validates_ciphertext(self) -> None:
        key = bytes.fromhex("133457799BBCDFF1")
        with self.assertRaises(TypeError):
            des.decrypt_ecb("ciphertext", key)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            des.decrypt_ecb(b"", key)
        with self.assertRaises(ValueError):
            des.decrypt_ecb(b"not-eight", key)
        with self.assertRaises(ValueError):
            des.decrypt_ecb(bytes(8), b"short")

    def test_decrypt_ecb_rejects_invalid_padding(self) -> None:
        key = bytes.fromhex("133457799BBCDFF1")
        # Encrypt a raw block that does not end in PKCS#7 padding. The block
        # cipher operation succeeds, but the ECB text wrapper must reject it.
        malformed_ciphertext, _ = des.encrypt_block(b"12345678", key)
        with self.assertRaises(ValueError):
            des.decrypt_ecb(malformed_ciphertext, key)


if __name__ == "__main__":
    unittest.main()
