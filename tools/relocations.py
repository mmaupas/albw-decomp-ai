"""Fail-closed ARM ELF REL validation; independent of the compiler and game dump.

Unknown symbols and linker rewrites are not proof of a byte match. Only the
selected function's section has a known placement. See AAELF32 relocation rules.
"""
import re

VERIFIER_VERSION = "identity-v1"
ADDRESS_LABEL = re.compile(r"(?:func|FUN|f|data|ro|G|bss)_([0-9a-fA-F]{8})\Z")


def resolve_symbol(symbol, section_bases, aliases=None):
    """Resolve to (address without Thumb bit, is_thumb), or None.

    Aliases must be explicit, reviewed identities, not guesses from a disassembly
    name or from the target instruction. Mangled names are deliberately refused.
    """
    section = symbol["shndx"]
    value = symbol["value"]
    thumb = symbol["type"] == 2 and bool(value & 1)
    if section == 0xFFF1:  # SHN_ABS
        return (value & ~1 if thumb else value), thumb
    if section in section_bases:
        return section_bases[section] + (value & ~1 if thumb else value), thumb
    if section != 0:
        return None
    if aliases and symbol["name"] in aliases:
        return aliases[symbol["name"]]
    match = ADDRESS_LABEL.fullmatch(symbol["name"])
    if match:
        address = int(match.group(1), 16)
        # An odd explicit function address carries its Thumb state.
        function = symbol["name"].startswith(("func_", "FUN_", "f_"))
        return (address & ~1, True) if function and address & 1 else (address, False)
    return None


def _branch_addend(word):
    value = (word & 0xFFFFFF) << 2
    return value - 0x4000000 if value & 0x2000000 else value


def validate_relocation(mine, target, kind, place, resolved):
    """Validate the complete linked word, including symbol identity and addend."""
    if resolved is None:
        return False
    address, thumb = resolved
    if kind == 2:  # R_ARM_ABS32, arithmetic is modulo 2**32
        return target == (((address + mine) | int(thumb)) & 0xFFFFFFFF)
    if kind not in (1, 28, 29):
        return False
    branch = (mine & 0x0E000000) == 0x0A000000
    blx = (mine & 0xFE000000) == 0xFA000000
    if not branch or (mine >> 28 == 0xF and not blx):
        return False
    if kind == 28 and not (blx or mine >> 24 == 0xEB):
        return False
    if kind != 28 and blx:
        return False
    # In REL objects the implicit branch addend excludes BLX's H bit.
    delta = address + _branch_addend(mine) - place
    if thumb:
        if kind != 28 or delta % 2 or not -(1 << 25) <= delta < (1 << 25):
            return False
        expected = 0xFA000000 | ((delta & 2) << 23) | ((delta >> 2) & 0xFFFFFF)
    else:
        if delta % 4 or not -(1 << 25) <= delta < (1 << 25):
            return False
        # A Thumb-call placeholder may be converted back to an ARM BL.
        opcode = 0xEB000000 if blx else mine & 0xFF000000
        expected = opcode | ((delta >> 2) & 0xFFFFFF)
    return target == expected


def word_matches(mine, target, relocation, place, section_bases, aliases=None):
    if mine is None or target is None:
        return False
    if relocation is None:
        return mine == target
    kind, symbol = relocation
    return validate_relocation(mine, target, kind, place,
                               resolve_symbol(symbol, section_bases, aliases))
