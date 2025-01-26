#!/usr/bin/env python3

import itertools
import json
from collections import defaultdict
from pathlib import Path

from utils import NoIndent, NoIndentEncoder

script_dir = Path(__file__).parent.resolve(True)
strings_dir = script_dir / 'extracted-strings'


def should_include_locations_dict(locations_dict: dict[str, list[str]]):
    feature_types = set(itertools.chain.from_iterable(locations_dict.values()))
    return len(feature_types) > 1 and 'strings' in feature_types


def main():
    with open(strings_dir / 'from-elfs.json', 'r', encoding='utf-8') as f:
        json_from_elfs: dict[str, dict] = json.load(f)

    inst_to_locations: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))

    for elf_path, features_dict in json_from_elfs.items():
        for feature_type, instances in features_dict.items():
            for inst in instances:
                pool = inst_to_locations[inst][elf_path]
                if feature_type not in pool:
                    pool.append(feature_type)

    filtered_inst_to_locations = {
        inst: locations_dict
        for inst, locations_dict in inst_to_locations.items()
        if should_include_locations_dict(locations_dict)
    }

    instances_by_locations_dict = defaultdict(list)
    for inst, locations_dict in filtered_inst_to_locations.items():
        new_locations_dict = defaultdict(list)
        for elf_path, feature_types in locations_dict.items():
            new_locations_dict[tuple(feature_types)].append(elf_path)
        locations_dict_as_key = tuple([
            (feature_types, tuple(elfs)) for feature_types, elfs in new_locations_dict.items()
        ])
        instances_by_locations_dict[locations_dict_as_key].append(inst)

    instances_by_locations_dict_as_list = [
        {
            'instances': instances,
            'locations': [
                {'feature_types': NoIndent(feature_types), 'elfs': elfs}
                for feature_types, elfs in locations_dict_as_key
            ],
        }
        for locations_dict_as_key, instances in sorted(instances_by_locations_dict.items(), key=lambda t: sum(len(elfs) for _, elfs in t[0]))
    ]

    instances_by_locations_dict_only_isolated_strings_as_list = [
        entry
        for entry in instances_by_locations_dict_as_list
        if any(loc['feature_types'].value == ('strings',) for loc in entry['locations'])
    ]

    with open(strings_dir / 'from-elfs-strings-matching-symbols.json', 'w', encoding='utf-8') as f:
        json.dump(instances_by_locations_dict_as_list, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    with open(strings_dir / 'from-elfs-isolated-strings-matching-symbols.json', 'w', encoding='utf-8') as f:
        json.dump(instances_by_locations_dict_only_isolated_strings_as_list, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)


if __name__ == '__main__':
    main()
