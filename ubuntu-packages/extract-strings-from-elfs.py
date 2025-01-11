#!/usr/bin/env python3

from collections import Counter
import json
from pathlib import Path
from elf import Elf
import subprocess

script_dir = Path(__file__).parent.resolve(True)
elfs_dir = script_dir / 'extracted-elfs'
out_dir = script_dir / 'extracted-strings'
out_dir.mkdir(exist_ok=True)

# # https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L62-L65
# # Read only data sections. This should be expanded.
# RODATA_SECTIONS = ['.rodata', '.rodata.str1.1', '.rodata.str1.4',
#                    '.rodata.str1.8', '.rodata.cst4', '.rodata.cst8',
#                    '.rodata.cst16', 'rodata']

# https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L70-L74
# characters to be removed when extracting strings
REMOVE_CHARACTERS = ['\a', '\b', '\v', '\f', '\x01', '\x02', '\x03', '\x04',
                     '\x05', '\x06', '\x0e', '\x0f', '\x10', '\x11', '\x12',
                     '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19',
                     '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x7f']

REMOVE_CHARACTERS_TABLE = str.maketrans({ch: '' for ch in REMOVE_CHARACTERS})

# https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L88-L90
# translation table for ASCII strings for the string
# to pass the isprintable() test
STRING_TRANSLATION_TABLE = str.maketrans({'\t': ' '})

STRING_CUTOFF_LENGTH = 4

def extract_strings_from_elf(elf_path: Path | str) -> dict:
    data = Elf.from_file(elf_path)
    headers: list[Elf.EndianElf.SectionHeader] = data.header.section_headers

    string_literals = []
    defined_symbols = []
    undefined_symbols = []

    for header in headers:
        if 'rodata' in header.name and header.name not in ('.rel.rodata', '.rela.rodata'):
            if header.name != '.rodata':
                print(f'unusual name of .rodata section {header.name!r}')
            if header.type == Elf.ShType.nobits:
                continue
            assert header.type == Elf.ShType.progbits, f'unexpected type {header.type!r} for {header.name!r} section in {elf_path.name}'
            body: bytes = header.body

            # https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L774-L795
            for s in body.split(b'\x00'):
                try:
                    decoded_strings = s.decode().splitlines()
                    for decoded_string in decoded_strings:
                        for rc in REMOVE_CHARACTERS:
                            if rc in decoded_string:
                                decoded_string = decoded_string.translate(REMOVE_CHARACTERS_TABLE)

                        if len(decoded_string) < STRING_CUTOFF_LENGTH:
                            continue
                        if decoded_string.isspace():
                            continue

                        translated_string = decoded_string.translate(STRING_TRANSLATION_TABLE)
                        if decoded_string.isascii():
                            # test the translated string
                            if translated_string.isprintable():
                                string_literals.append(decoded_string)
                        else:
                            string_literals.append(decoded_string)
                except UnicodeDecodeError:
                    pass
        elif header.type == Elf.ShType.dynsym:
            assert header.name == '.dynsym'
            entries: list[Elf.EndianElf.DynsymSectionEntry] = header.body.entries

            # https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L676-L687
            for idx, entry in enumerate(entries):
                symbol_name = entry.name or ''
                if entry.type not in (Elf.SymbolType.func, Elf.SymbolType.object):
                    # print(f'Skipping symbol {symbol_name!r} because it has type {entry.type!r}')
                    continue
                if entry.bind != Elf.SymbolBinding.global_symbol:
                    # print(f'Skipping symbol {symbol_name!r} because it has binding {entry.bind!r}')
                    continue

                if entry.sh_idx_special == Elf.SectionHeaderIdxSpecial.undefined:
                    undefined_symbols.append(symbol_name)
                else:
                    defined_symbols.append(symbol_name)

    return {
        'strings': string_literals,
        'defined_symbols': defined_symbols,
        'undefined_symbols': undefined_symbols,
    }

def extract_strings_from_blob(path: Path) -> list[str]:
    strings_out = subprocess.check_output(['strings', '--', path], encoding='utf-8')
    return strings_out.splitlines()

def main():
    json_from_elfs = {}
    json_from_blobs = {}
    for elf_path in sorted(elfs_dir.iterdir()):
        json_from_elfs[elf_path.name] = extract_strings_from_elf(elf_path)
        json_from_blobs[elf_path.name] = extract_strings_from_blob(elf_path)

    with open(out_dir / 'from-elfs.json', 'w', encoding='utf-8') as f:
        json.dump(json_from_elfs, f, ensure_ascii=False, allow_nan=False, indent=4)

    with open(out_dir / 'from-blobs.json', 'w', encoding='utf-8') as f:
        json.dump(json_from_blobs, f, ensure_ascii=False, allow_nan=False, indent=4)

if __name__ == '__main__':
    main()
