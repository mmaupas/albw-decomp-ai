import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import common
import fn
from relocations import resolve_symbol, validate_relocation, word_matches


def symbol(name="func_00102000", value=0, section=0, kind=2):
    return dict(name=name, value=value, shndx=section, type=kind)


class RelocationTests(unittest.TestCase):
    def test_call_identity_and_condition(self):
        self.assertTrue(word_matches(0xEBFFFFFE, 0xEB0003FE,
                                    (28, symbol()), 0x101000, {}))
        for target in (0xEB0003FF, 0x1B0003FE, 0xEA0003FE, 0xE1A00000):
            self.assertFalse(word_matches(0xEBFFFFFE, target,
                                         (28, symbol()), 0x101000, {}))

    def test_backward_branch_and_nonzero_addend(self):
        self.assertTrue(validate_relocation(0xEAFFFFFE, 0xEAFFFBFE, 29,
                                           0x102000, (0x101000, False)))
        self.assertTrue(validate_relocation(0xEBFFFFFF, 0xEB0003FF, 28,
                                           0x101000, (0x102000, False)))

    def test_thumb_call_h_bit_and_rel_addend(self):
        for address, expected in ((0x102000, 0xFA0003FE), (0x102002, 0xFB0003FE)):
            self.assertTrue(validate_relocation(0xEBFFFFFE, expected, 28,
                                               0x101000, (address, True)))
            # H is not part of the REL object's implicit addend.
            self.assertTrue(validate_relocation(0xFBFFFFFE, expected, 28,
                                               0x101000, (address, True)))
        self.assertFalse(validate_relocation(0xEAFFFFFE, 0xFA0003FE, 29,
                                            0x101000, (0x102000, True)))
        self.assertFalse(validate_relocation(0x1BFFFFFE, 0xFA0003FE, 28,
                                            0x101000, (0x102000, True)))

    def test_absolute_addends_and_thumb_pointer(self):
        for addend in (0, 12, 0xFFFFFFFC):
            expected = (0x700000 + addend) & 0xFFFFFFFF
            self.assertTrue(validate_relocation(addend, expected, 2, 0, (0x700000, False)))
            self.assertFalse(validate_relocation(addend, expected + 4, 2, 0, (0x700000, False)))
        self.assertTrue(validate_relocation(4, 0x102005, 2, 0, (0x102000, True)))

    def test_unknown_relocations_never_pass_equal_words(self):
        for kind, name in ((99, "func_00102000"), (28, "unknown"), (2, "unknown")):
            self.assertFalse(word_matches(0xEBFFFFFE, 0xEBFFFFFE,
                                         (kind, symbol(name)), 0x101000, {}))
        self.assertFalse(word_matches(0, 0x700000, (2, symbol("G_00700000", section=2)), 0, {}))

    def test_no_relocation_means_exact_bytes(self):
        self.assertTrue(word_matches(0xEB000012, 0xEB000012, None, 0, {}))
        self.assertFalse(word_matches(0xEB000012, 0xEB000013, None, 0, {}))
        self.assertFalse(word_matches(None, None, None, 0, {}))

    def test_range_alignment_and_opcode(self):
        for address in (0x102002, 0x3010000):
            self.assertFalse(validate_relocation(0xEBFFFFFE, 0xEB0003FE, 28,
                                                0x101000, (address, False)))
        self.assertFalse(validate_relocation(0xE1A00000, 0xE1A00000, 28, 0, (0, False)))

    def test_only_explicit_symbol_identities(self):
        for name in ("func_00102000", "FUN_00102000", "G_00102000", "ro_00102000",
                     "data_00102000", "bss_00102000"):
            self.assertEqual(resolve_symbol(symbol(name), {}), (0x102000, False))
        for name in ("_Z13func_00102000v", "func_00102000_extra", "unknown00102000"):
            self.assertIsNone(resolve_symbol(symbol(name), {}))
        self.assertEqual(resolve_symbol(symbol("local", 0x15, 3), {3: 0x100000}),
                         (0x100014, True))
        self.assertEqual(resolve_symbol(symbol("absolute", 0x700000, 0xFFF1, 1), {}),
                         (0x700000, False))
        self.assertIsNone(resolve_symbol(symbol("local", 0x10, 4), {3: 0x100000}))


class BinaryTests(unittest.TestCase):
    def test_wrong_binary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "code.bin")
            Path(path).write_bytes(b"not a game")
            with self.assertRaisesRegex(ValueError, "Expected USA"):
                common.load_binary(path)
            with patch.object(common, "BINARY_SIZE", 10):
                with self.assertRaises(ValueError):
                    common.load_binary(path)
            with patch.object(common, "BINARY_SIZE", 10), patch.object(
                    common, "BINARY_SHA1", hashlib.sha1(b"not a game").hexdigest()):
                self.assertEqual(common.load_binary(path), b"not a game")

    def test_import_did_not_load_binary(self):
        self.assertIsNone(fn.CODE)

    def test_check_rejects_interior_before_loading_binary(self):
        with patch.object(fn, "load_code") as load:
            with self.assertRaisesRegex(ValueError, "exact function start"):
                fn.cmd_check("unused.c", fn.STARTS[0] + 1)
            load.assert_not_called()


class ElfTests(unittest.TestCase):
    def _object(self, directory, offset=0):
        strings = b"\0wrong\0func_00102000\0"
        null_symbol = bytes(16)
        first = null_symbol + struct.pack("<IIIBBH", 1, 0, 0, 0x12, 0, 0)
        second = null_symbol + struct.pack("<IIIBBH", 7, 0, 0, 0x12, 0, 0)
        # type, data, link, info, entry size; REL must use second SYMTAB.
        specs = [(0, b"", 0, 0, 0), (1, bytes(4), 0, 0, 0),
                 (3, strings, 0, 0, 0), (2, first, 2, 0, 16),
                 (2, second, 2, 0, 16),
                 (9, struct.pack("<II", offset, (1 << 8) | 28), 4, 1, 8)]
        data = bytearray(52)
        headers = []
        for kind, payload, link, info, entry_size in specs:
            headers.append(struct.pack("<10I", 0, kind, 0, 0, len(data), len(payload),
                                       link, info, 4, entry_size))
            data.extend(payload)
        shoff = len(data)
        data.extend(b"".join(headers))
        data[:7] = b"\x7fELF\x01\x01\x01"
        struct.pack_into("<HH", data, 16, 1, 40)
        struct.pack_into("<I", data, 32, shoff)
        struct.pack_into("<HHH", data, 46, 40, len(specs), 2)
        path = os.path.join(directory, "fixture.o")
        Path(path).write_bytes(data)
        return path

    def test_relocation_uses_its_own_symbol_table(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, rels = fn.parse_elf(self._object(directory))
        self.assertEqual(rels[1][0][2]["name"], "func_00102000")
        self.assertEqual(rels[1][0][2]["binding"], 1)

    def test_malformed_section_and_record_layouts_are_rejected(self):
        # Header index, field byte offset, value: never silently floor-divide a record.
        cases = [(5, 20, 7), (5, 36, 0), (4, 20, 31), (4, 36, 8),
                 (5, 24, 99), (5, 28, 99), (1, 16, 0xFFFFFFF0)]
        with tempfile.TemporaryDirectory() as directory:
            for index, field, value in cases:
                with self.subTest(index=index, field=field, value=value):
                    path = self._object(directory)
                    data = bytearray(Path(path).read_bytes())
                    shoff = struct.unpack_from("<I", data, 32)[0]
                    struct.pack_into("<I", data, shoff + index * 40 + field, value)
                    Path(path).write_bytes(data)
                    with self.assertRaises(ValueError):
                        fn.parse_elf(path)
            Path(path).write_bytes(b"\\x7fELF")
            with self.assertRaises(ValueError):
                fn.parse_elf(path)

    def test_unaligned_relocation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "unaligned"):
                fn.parse_elf(self._object(directory, offset=1))


if __name__ == "__main__":
    unittest.main()
