#!/usr/bin/env python3

import itertools
import json
from pathlib import Path
from typing import Any, Literal

script_dir = Path(__file__).parent.resolve(True)
strings_dir = script_dir / 'extracted-strings'


def read_json(file_path: Path) -> dict[str, Any]:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def main():
    json_from_elfs = read_json(strings_dir / 'from-elfs.json')
    json_from_blobs = read_json(strings_dir / 'from-blobs.json')

    json_in_blobs_but_not_elfs: dict[str, dict[Literal['strings'], list[str]]] = {}

    for elf_path, features_dict in json_from_blobs.items():
        strings_from_blob = features_dict['strings']
        strings_from_elf = set(
            itertools.chain.from_iterable(json_from_elfs[elf_path].values())
        )
        processed_strings = set()
        missing_strings = []
        for s in strings_from_blob:
            if s in processed_strings:
                continue
            if s not in strings_from_elf:
                missing_strings.append(s)
            processed_strings.add(s)

        json_in_blobs_but_not_elfs[elf_path] = {
            'strings': missing_strings,
        }

    with open(
        strings_dir / 'from-blobs-missing-from-elfs.json', 'w', encoding='utf-8'
    ) as f:
        json.dump(
            json_in_blobs_but_not_elfs, f, ensure_ascii=False, allow_nan=False, indent=2
        )


if __name__ == '__main__':
    main()
