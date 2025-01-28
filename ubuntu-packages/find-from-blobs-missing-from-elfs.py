#!/usr/bin/env python3

import itertools
import json
from pathlib import Path
from typing import Any

script_dir = Path(__file__).parent.resolve(True)
strings_dir = script_dir / 'extracted-strings'


def read_json(file_path: Path) -> dict[str, Any]:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def main() -> None:
    json_from_elfs: dict[str, dict[str, list[str]]] = read_json(
        strings_dir / 'from-elfs.json'
    )
    json_from_blobs: dict[str, dict[str, list[str]]] = read_json(
        strings_dir / 'from-blobs.json'
    )

    json_in_blobs_but_not_elfs: dict[str, dict[str, list[str]]] = {}

    for elf_path, sections_dict in json_from_blobs.items():
        strings_from_elf = set(
            itertools.chain.from_iterable(json_from_elfs[elf_path].values())
        )
        from_blobs_but_not_elfs_entry = {}
        for section_name, strings_from_blob in sections_dict.items():
            processed_strings = set()
            missing_strings = []
            for s in strings_from_blob:
                if s in processed_strings:
                    continue
                if s not in strings_from_elf:
                    missing_strings.append(s)
                processed_strings.add(s)
            from_blobs_but_not_elfs_entry[section_name] = missing_strings

        json_in_blobs_but_not_elfs[elf_path] = from_blobs_but_not_elfs_entry

    with open(
        strings_dir / 'from-blobs-missing-from-elfs.json', 'w', encoding='utf-8'
    ) as f:
        json.dump(
            json_in_blobs_but_not_elfs, f, ensure_ascii=False, allow_nan=False, indent=2
        )


if __name__ == '__main__':
    main()
