#!/usr/bin/env python3

import json
from pathlib import Path
from elf import Elf
import subprocess
import re
from tqdm import tqdm

script_dir = Path(__file__).parent.resolve(True)
elfs_dir = script_dir / 'extracted-elfs'
out_dir = script_dir / 'extracted-strings'
out_dir.mkdir(exist_ok=True)

# https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L62-L65
# Read only data sections. This should be expanded.
RODATA_SECTIONS = ['.rodata', '.rodata.str1.1', '.rodata.str1.4',
                   '.rodata.str1.8', '.rodata.cst4', '.rodata.cst8',
                   '.rodata.cst16', 'rodata']

STRING_SEPARATOR_REGEX = re.compile(r'[\x00-\x08\x0a-\x1f\x7f\ufffd]+')

# https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L88-L90
# translation table for ASCII strings for the string
# to pass the isprintable() test
STRING_TRANSLATION_TABLE = str.maketrans({'\t': ' '})

STRING_CUTOFF_LENGTH = 4

def extract_strings_from_elf(elf_path: Path | str) -> dict:
    data = Elf.from_file(elf_path)
    headers: list[Elf.EndianElf.SectionHeader] = data.header.section_headers

    string_literals = []
    defined_functions = []
    undefined_functions = []
    defined_objects = []
    undefined_objects = []

    for header in headers:
        if header.name in RODATA_SECTIONS:
            if header.type == Elf.ShType.nobits:
                continue
            assert header.type == Elf.ShType.progbits, f'unexpected type {header.type!r} for {header.name!r} section in {elf_path.name}'
            body: bytes = header.body

            # https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L774-L795
            for s in body.split(b'\x00'):
                decoded_s = s.decode('utf-8', errors='replace')
                # We look for the last UTF-8 decode error, which is indicated by the
                # U+FFFD REPLACEMENT CHARACTER. If we find it, we only consider the part
                # after it until the b'\x00' byte and ignore everything before it. The
                # logic is that strings in C are null-terminated, so any actual string
                # literal in C source code will end with b'\x00', but it can start
                # anywhere in the .rodata section right after any "garbage" (some generic
                # read-only data not coming from a string literal). If we are lucky, this
                # garbage will fail to decode to UTF-8 somewhere, in which case we can
                # limit the range where we look for strings, which will filter out the
                # nonsense strings found in the binary garbage from the output.
                repl_ch_idx = decoded_s.rfind('\ufffd')
                if repl_ch_idx != -1:
                    decoded_s = decoded_s[repl_ch_idx + 1:]
                decoded_strings = STRING_SEPARATOR_REGEX.split(decoded_s)
                for decoded_string in decoded_strings:
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
                            print(f'Skipping non-printable ASCII string {decoded_string!r}')
                    else:
                        string_literals.append(decoded_string)
        elif header.type == Elf.ShType.dynsym:
            assert header.name == '.dynsym'
            entries: list[Elf.EndianElf.DynsymSectionEntry] = header.body.entries

            # https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/UnpackParser.py#L676-L687
            for entry in entries:
                symbol_name = entry.name or ''
                if entry.bind != Elf.SymbolBinding.global_symbol:
                    # print(f'Skipping symbol {symbol_name!r} because it has binding {entry.bind!r}')
                    continue

                if entry.type == Elf.SymbolType.func:
                    if entry.sh_idx_special == Elf.SectionHeaderIdxSpecial.undefined:
                        undefined_functions.append(symbol_name)
                    else:
                        defined_functions.append(symbol_name)

                if entry.type == Elf.SymbolType.object:
                    if entry.sh_idx_special == Elf.SectionHeaderIdxSpecial.undefined:
                        undefined_objects.append(symbol_name)
                    else:
                        defined_objects.append(symbol_name)

    return {
        'strings': string_literals,
        'defined_functions': defined_functions,
        'undefined_functions': undefined_functions,
        'defined_objects': defined_objects,
        'undefined_objects': undefined_objects,
    }

def extract_strings_from_blob(path: Path) -> list[str]:
    strings_out = subprocess.check_output(['strings', '--', path], encoding='utf-8')
    return strings_out.splitlines()

def main():
    json_from_elfs = {}
    json_from_blobs = {}
    for elf_path in tqdm(sorted(elfs_dir.iterdir())):
        json_from_elfs[elf_path.name] = extract_strings_from_elf(elf_path)
        json_from_blobs[elf_path.name] = extract_strings_from_blob(elf_path)

    with open(out_dir / 'from-elfs.json', 'w', encoding='utf-8') as f:
        json.dump(json_from_elfs, f, ensure_ascii=False, allow_nan=False, indent=4)

    with open(out_dir / 'from-blobs.json', 'w', encoding='utf-8') as f:
        json.dump(json_from_blobs, f, ensure_ascii=False, allow_nan=False, indent=4)

if __name__ == '__main__':
    main()
