#!/usr/bin/env python3

from collections import defaultdict
import copy
import json
from pathlib import Path

script_dir = Path(__file__).parent.resolve(True)
strings_dir = script_dir / 'extracted-strings'

PACKAGE_NAME_SUFFIX = '_amd64.deb'
PACKAGE_AND_ELF_NAME_SEPARATOR = f'{PACKAGE_NAME_SUFFIX}-'

def split_full_elf_name(full_elf_name):
    package_name, elf_name = full_elf_name.split(PACKAGE_AND_ELF_NAME_SEPARATOR, maxsplit=1)
    assert PACKAGE_AND_ELF_NAME_SEPARATOR not in elf_name, f'{full_elf_name!r} contains {PACKAGE_AND_ELF_NAME_SEPARATOR!r} more than once'
    return package_name + PACKAGE_NAME_SUFFIX, elf_name

def main():
    with open(strings_dir / 'from-elfs.json', 'r', encoding='utf-8') as f:
        json_from_elfs: dict[str, dict] = json.load(f)

    inverse_map = defaultdict(lambda: defaultdict(list))
    for elf_name, features_dict in json_from_elfs.items():
        for feature_type, instances in features_dict.items():
            pool = inverse_map[feature_type]
            processed_instances = set()
            for inst in instances:
                if inst in processed_instances:
                    continue
                pool[inst].append(elf_name)
                processed_instances.add(inst)

    features_dict_template = {feature_type: [] for feature_type in inverse_map}

    grouped_by_elf_set = defaultdict(lambda: copy.deepcopy(features_dict_template))

    FEATURE_GROUPS = ['elf_unique', 'package_unique', 'not_unique']
    elf_info_template = {feat_group: copy.deepcopy(features_dict_template) for feat_group in FEATURE_GROUPS}

    packages_info = defaultdict(dict)
    for elf in json_from_elfs:
        package_name, elf_name = split_full_elf_name(elf)
        packages_info[package_name][elf_name] = copy.deepcopy(elf_info_template)

    packages_info = dict(packages_info)

    for feature_type, instances_dict in inverse_map.items():
        for inst, elfs in instances_dict.items():
            if len(elfs) == 1:
                package_name, elf_name = split_full_elf_name(elfs[0])
                packages_info[package_name][elf_name]['elf_unique'][feature_type].append(inst)
            else:
                first_package_name, _ = split_full_elf_name(elfs[0])
                if all(split_full_elf_name(elf)[0] == first_package_name for elf in elfs):
                    feat_group = 'package_unique'
                else:
                    feat_group = 'not_unique'
                    grouped_by_elf_set[tuple(elfs)][feature_type].append(inst)
                for elf in elfs:
                    package_name, elf_name = split_full_elf_name(elf)
                    packages_info[package_name][elf_name][feat_group][feature_type].append(inst)

    ordered_grouped_by_elf_set = [
        {'elfs': elfs, **features_dict}
        for elfs, features_dict in sorted(grouped_by_elf_set.items(), key=lambda t: sum(len(instances) for instances in t[1].values()), reverse=True)
    ]

    with open(strings_dir / 'from-elfs-classified-per-packages.json', 'w', encoding='utf-8') as f:
        json.dump(packages_info, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(strings_dir / 'from-elfs-duplicate-grouped.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_grouped_by_elf_set, f, ensure_ascii=False, allow_nan=False, indent=2)


if __name__ == "__main__":
    main()
