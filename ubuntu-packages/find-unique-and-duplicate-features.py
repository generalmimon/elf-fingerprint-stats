#!/usr/bin/env python3

import copy
import itertools
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from operator import itemgetter
from pathlib import Path

from utils import NoIndent, NoIndentEncoder

ELF_PATH_REGEX = re.compile(r'(.*)/(.*_amd64\.deb)-(.*)')

@dataclass(frozen=True)
class ElfPath:
    source_pkg: str
    binary_pkg: str
    name: str

    @staticmethod
    def from_str(s: str) -> 'ElfPath':
        match = ELF_PATH_REGEX.fullmatch(s)
        source_pkg, binary_pkg, name = match.groups()
        return ElfPath(source_pkg, binary_pkg, name)

    @property
    def pkg_path(self) -> str:
        return f'{self.source_pkg}/{self.binary_pkg}'

    def __str__(self) -> str:
        return f'{self.pkg_path}-{self.name}'

def read_from_elfs_json(json_path: Path) -> dict[ElfPath, dict[str, list[str]]]:
    with open(json_path, 'r', encoding='utf-8') as f:
        orig_json = json.load(f)
        return {ElfPath.from_str(elf_path_str): features_dict for elf_path_str, features_dict in orig_json.items()}

def generate_dumps(json_path: Path, output_dir: Path) -> None:
    elf_to_features = read_from_elfs_json(json_path)

    inverse_map: dict[str, dict[str, list[ElfPath]]] = defaultdict(lambda: defaultdict(list))
    for elf_path, features_dict in elf_to_features.items():
        for feature_type, instances in features_dict.items():
            pool = inverse_map[feature_type]
            processed_instances = set()
            for inst in instances:
                if inst in processed_instances:
                    continue
                pool[inst].append(elf_path)
                processed_instances.add(inst)

    grouped_by_elf_set = defaultdict(lambda: defaultdict(list))

    UNIQ_CLASSES = ['elf_unique', 'binary_pkg_unique', 'source_pkg_unique', 'not_unique']
    uniq_classes_dict_template = {uniq_class: [] for uniq_class in UNIQ_CLASSES}
    elf_info_template = defaultdict(lambda: copy.deepcopy(uniq_classes_dict_template))

    packages_info = defaultdict(dict)
    for elf_path in elf_to_features:
        packages_info[elf_path.pkg_path][elf_path.name] = copy.deepcopy(elf_info_template)

    packages_info = dict(packages_info)
    aggr_features = defaultdict(lambda: copy.deepcopy(uniq_classes_dict_template))

    aggr_by_num_origins_counts = {key: defaultdict(Counter) for key in ('elfs', 'binary_pkgs', 'source_pkgs')}

    for feature_type, instances_dict in inverse_map.items():
        for inst, elfs in instances_dict.items():
            num_elfs = len(elfs)
            num_binary_pkgs = len(set(elf_path.binary_pkg for elf_path in elfs))
            num_source_pkgs = len(set(elf_path.source_pkg for elf_path in elfs))
            if num_elfs == 1:
                uniq_class = 'elf_unique'
            elif num_binary_pkgs == 1:
                uniq_class = 'binary_pkg_unique'
            elif num_source_pkgs == 1:
                uniq_class = 'source_pkg_unique'
            else:
                uniq_class = 'not_unique'
                grouped_by_elf_set[tuple(elfs)][feature_type].append(inst)
            for elf_path in elfs:
                packages_info[elf_path.pkg_path][elf_path.name][feature_type][uniq_class].append(inst)
            aggr_features[feature_type][uniq_class].append((inst, (num_source_pkgs, num_binary_pkgs, num_elfs)))
            aggr_by_num_origins_counts['elfs'][feature_type][num_elfs] += 1
            aggr_by_num_origins_counts['binary_pkgs'][feature_type][num_binary_pkgs] += 1
            aggr_by_num_origins_counts['source_pkgs'][feature_type][num_source_pkgs] += 1

    if 'strings' in aggr_features:
        aggr_strings_iter = aggr_features['strings'].items()
    else:
        # We're probably dealing with `from-blobs.json`, where we want to treat
        # everything as a string.
        aggr_strings_iter = itertools.chain.from_iterable(d.items() for d in aggr_features.values())

    aggr_strings_by_len = defaultdict(lambda: copy.deepcopy(uniq_classes_dict_template))
    for uniq_class, strings_list in aggr_strings_iter:
        for s, _ in strings_list:
            aggr_strings_by_len[len(s)][uniq_class].append(s)

    ordered_aggr_strings_by_len = {
        len_s: strings_dict
        for len_s, strings_dict in sorted(aggr_strings_by_len.items(), key=itemgetter(0))
    }
    ordered_aggr_strings_by_len_counts = {
        len_s: NoIndent({uniq_class: len(strings_list) for uniq_class, strings_list in strings_dict.items()})
        for len_s, strings_dict in ordered_aggr_strings_by_len.items()
    }

    ordered_aggr_features = {
        feature_type: {
            uniq_class: {tup[0]: NoIndent(tup[1]) for tup in sorted(instances, key=itemgetter(1), reverse=True)}
            for uniq_class, instances in features_dict.items()
        }
        for feature_type, features_dict in aggr_features.items()
    }

    ordered_grouped_by_elf_set = [
        {'elfs': list(map(str, elf_paths)), **features_dict}
        for elf_paths, features_dict in sorted(grouped_by_elf_set.items(), key=lambda t: sum(len(instances) for instances in t[1].values()), reverse=True)
    ]

    ordered_aggr_by_num_origins_counts = {
        key: {feature_type: {k: v for k, v in sorted(counter.items(), key=itemgetter(0))} for feature_type, counter in counters_dict.items()}
        for key, counters_dict in aggr_by_num_origins_counts.items()
    }

    with open(output_dir / 'classified-aggregated.json', 'w', encoding='utf-8') as f:
        comment = 'The meaning of the numbers is [num_source_pkgs, num_binary_pkgs, num_elfs]'
        json.dump({'$comment': comment, **ordered_aggr_features}, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    with open(output_dir / 'classified-aggregated-strings-by-len.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_aggr_strings_by_len, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(output_dir / 'classified-aggregated-strings-by-len-counts.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_aggr_strings_by_len_counts, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    with open(output_dir / 'aggregated-by-num-origins-counts.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_aggr_by_num_origins_counts, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(output_dir / 'classified-per-packages.json', 'w', encoding='utf-8') as f:
        json.dump(packages_info, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(output_dir / 'duplicate-grouped.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_grouped_by_elf_set, f, ensure_ascii=False, allow_nan=False, indent=2)

def usage(prog_name: str) -> None:
    print(f'Usage: {prog_name} <input-json> [<output-dir>]', file=sys.stderr)

def main(argv: list[str]) -> int:
    prog_name = argv[0]
    num_args = len(argv) - 1
    if num_args not in (1, 2):
        print(f'Error: expected 1 or 2 positional arguments, but got {num_args}', file=sys.stderr)
        print(file=sys.stderr)
        usage(prog_name)
        return 1

    input_json = Path(argv[1])
    if input_json.suffix != '.json':
        print(f'Error: expected <input-json> to have a .json extension, but got {argv[1]!r}', file=sys.stderr)
        print(file=sys.stderr)
        usage(prog_name)
        return 1

    try:
        output_dir = argv[2]
    except IndexError:
        output_dir = input_json.parent / f'dumps-{input_json.stem}'
        print(f'Info: <output-dir> not given, using {output_dir}/', file=sys.stderr)
    else:
        output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    generate_dumps(input_json, output_dir)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
