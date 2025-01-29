#!/usr/bin/env python3

import copy
import itertools
import json
import re
import sys
from collections import Counter, defaultdict, namedtuple
from collections.abc import Collection
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

    def __str__(self) -> str:
        return f'{self.source_pkg}/{self.binary_pkg}-{self.name}'

def read_from_elfs_json(json_path: Path) -> dict[ElfPath, dict[str, list[str]]]:
    with open(json_path, 'r', encoding='utf-8') as f:
        orig_json = json.load(f)
        return {ElfPath.from_str(elf_path_str): features_dict for elf_path_str, features_dict in orig_json.items()}

NumOrigins = namedtuple('NumOrigins', ('num_source_pkgs', 'num_binary_pkgs', 'num_elfs'))

JSON_COMMENT = f"The meaning of the numbers is [{', '.join(NumOrigins._fields)}]"

def get_num_origins(elf_paths: Collection[ElfPath]) -> NumOrigins:
    num_elfs = len(elf_paths)
    num_binary_pkgs = len(set(elf_path.binary_pkg for elf_path in elf_paths))
    num_source_pkgs = len(set(elf_path.source_pkg for elf_path in elf_paths))
    return NumOrigins(
        num_elfs=num_elfs,
        num_binary_pkgs=num_binary_pkgs,
        num_source_pkgs=num_source_pkgs,
    )

def get_uniq_class(num_origins: NumOrigins) -> str:
    if num_origins.num_elfs == 1:
        return 'elf_unique'
    if num_origins.num_binary_pkgs == 1:
        return 'binary_pkg_unique'
    if num_origins.num_source_pkgs == 1:
        return 'source_pkg_unique'

    return 'not_unique'

def generate_dumps(json_path: Path, output_dir: Path, global_uniqueness: bool) -> None:
    """Generate JSON dumps from the input JSON file with extracted features.

    Parameters
    ----------
    json_path : Path
        Input JSON with extracted features. Expected input JSON files are
        `from-elfs.json`, `from-blobs.json` or
        `from-blobs-missing-from-elfs.json`.
    output_dir : Path
        Output directory for generated JSON dumps.
    global_uniqueness : bool
        Controls how uniqueness is determined.

        If `True`, uniqueness of each feature is judged "globally" regardless of
        the feature type. That is, if the same string is found as a defined
        symbol in one ELF binary and as an undefined symbol in another ELF
        binary, then it cannot be ELF-unique in either feature type.

        If `False`, uniqueness is determined only within each feature type. This
        means that the uniqueness of, for example, a defined symbol is not
        affected by occurrences of the same string in other feature types.
    """

    elf_to_features = read_from_elfs_json(json_path)

    elfs_having_feature_type: dict[str, list[ElfPath]] = defaultdict(list)
    inst_to_locations: dict[str, dict[str, list[ElfPath]]] = defaultdict(dict)
    for elf_path, features_dict in elf_to_features.items():
        for feature_type, instances in features_dict.items():
            if instances:
                elfs_having_feature_type[feature_type].append(elf_path)
            for inst in instances:
                locations_dict = inst_to_locations[inst]
                if feature_type not in locations_dict:
                    locations_dict[feature_type] = []
                elif locations_dict[feature_type][-1] == elf_path:
                    continue
                locations_dict[feature_type].append(elf_path)

    num_unique_feature_type_instances = Counter()
    for inst, locations_dict in inst_to_locations.items():
        for feature_type in locations_dict:
            num_unique_feature_type_instances[feature_type] += 1

    num_feature_type_origins_and_counts = {
        feature_type: {'count': num_unique_feature_type_instances[feature_type], 'origins': get_num_origins(elfs)}
        for feature_type, elfs in elfs_having_feature_type.items()
    }
    sorted_feature_types = [
        feature_type
        for feature_type, _ in sorted(
            num_feature_type_origins_and_counts.items(),
            key=lambda t: t[1]['count'],
            reverse=True,
        )
    ]
    # This splitting of feature types based on the "at least 5 source packages"
    # condition is done because of the `from-blobs-missing-from-elfs.json`,
    # because there are some ELF section names that have many unique strings but
    # they only occur in 1-2 source packages (so they don't give a general
    # answer answer to ELF fingerprinting).
    sorted_feature_types = [
        feature_type for feature_type in sorted_feature_types
        if num_feature_type_origins_and_counts[feature_type]['origins'].num_source_pkgs >= 5
    ] + [
        feature_type for feature_type in sorted_feature_types
        if num_feature_type_origins_and_counts[feature_type]['origins'].num_source_pkgs < 5
    ]

    with open(output_dir / 'feature-types-aggregated-counts.json', 'w', encoding='utf-8') as f:
        json_body = {
            '$comment': f"The meaning of the numbers in 'origins' is [{', '.join(NumOrigins._fields)}]",
            'data': {
                feature_type: NoIndent(num_feature_type_origins_and_counts[feature_type])
                for feature_type in sorted_feature_types
            }
        }
        json.dump(json_body, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    grouped_by_elf_set = defaultdict(lambda: defaultdict(list))

    UNIQ_CLASSES = ['elf_unique', 'binary_pkg_unique', 'source_pkg_unique', 'not_unique']
    uniq_classes_dict_template = {uniq_class: [] for uniq_class in UNIQ_CLASSES}

    elf_to_features_classified = {
        str(elf_path): {
            feature_type: copy.deepcopy(uniq_classes_dict_template)
            for feature_type in features_dict
        }
        for elf_path, features_dict in elf_to_features.items()
    }
    aggr_features = {
        feature_type: copy.deepcopy(uniq_classes_dict_template)
        for feature_type in sorted_feature_types
    }
    aggr_by_num_origins_counts = {key: defaultdict(Counter) for key in ('elfs', 'binary_pkgs', 'source_pkgs')}

    for inst, locations_dict in inst_to_locations.items():
        if global_uniqueness:
            all_elfs_with_inst = set(itertools.chain.from_iterable(locations_dict.values()))
            num_origins = get_num_origins(all_elfs_with_inst)
            uniq_class = get_uniq_class(num_origins)

        for feature_type, elfs in locations_dict.items():
            local_num_origins = get_num_origins(elfs)
            local_uniq_class = get_uniq_class(local_num_origins)
            if not global_uniqueness:
                num_origins = local_num_origins
                uniq_class = local_uniq_class

            if uniq_class == 'not_unique':
                grouped_by_elf_set[tuple(elfs)][feature_type].append(inst)

            aggr_features[feature_type][uniq_class].append((inst, local_num_origins))
            aggr_by_num_origins_counts['elfs'][feature_type][num_origins.num_elfs] += 1
            aggr_by_num_origins_counts['binary_pkgs'][feature_type][num_origins.num_binary_pkgs] += 1
            aggr_by_num_origins_counts['source_pkgs'][feature_type][num_origins.num_source_pkgs] += 1

            for elf_path in elfs:
                elf_to_features_classified[str(elf_path)][feature_type][uniq_class].append(inst)

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
        key: {
            feature_type: {k: v for k, v in sorted(counters_dict[feature_type].items(), key=itemgetter(0))}
            for feature_type in sorted_feature_types
        }
        for key, counters_dict in aggr_by_num_origins_counts.items()
    }

    with open(output_dir / 'classified-aggregated.json', 'w', encoding='utf-8') as f:
        json.dump({'$comment': JSON_COMMENT, **ordered_aggr_features}, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    with open(output_dir / 'classified-aggregated-strings-by-len.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_aggr_strings_by_len, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(output_dir / 'classified-aggregated-strings-by-len-counts.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_aggr_strings_by_len_counts, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    with open(output_dir / 'aggregated-by-num-origins-counts.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_aggr_by_num_origins_counts, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(output_dir / 'classified-per-elfs.json', 'w', encoding='utf-8') as f:
        json.dump(elf_to_features_classified, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(output_dir / 'not-unique-grouped-by-elf-set.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_grouped_by_elf_set, f, ensure_ascii=False, allow_nan=False, indent=2)

def usage(prog_name: str) -> None:
    print(file=sys.stderr)
    print(f'Usage: {prog_name} <input-json> <uniqueness> [<output-dir>]', file=sys.stderr)
    print(
        "\n"
        "Arguments:\n"
        "  <input-json>\n"
        "        Input JSON with extracted features (from-elfs.json, from-blobs.json\n"
        "        or from-blobs-missing-from-elfs.json)\n"
        "  <uniqueness>\n"
        "        Controls whether the uniqueness is determined within each feature type\n"
        "        ('local') or across feature types ('global')\n"
        "  <output-dir>\n"
        "        Output directory for generated JSON dumps (optional)\n"
        ,
        file=sys.stderr,
        end='',
    )

def main(argv: list[str]) -> int:
    prog_name = argv[0]
    num_args = len(argv) - 1
    if num_args not in (2, 3):
        print(f'Error: expected 2 or 3 positional arguments, but got {num_args}', file=sys.stderr)
        usage(prog_name)
        return 1

    input_json = Path(argv[1])
    if input_json.suffix != '.json':
        print(f'Error: expected <input-json> to have a .json extension, but got {argv[1]!r}', file=sys.stderr)
        usage(prog_name)
        return 1

    uniqueness = argv[2]
    if uniqueness not in ('local', 'global'):
        print(f"Error: expected <uniqueness> to be 'local' or 'global', but got {uniqueness!r}", file=sys.stderr)
        usage(prog_name)
        return 1

    try:
        output_dir_str = argv[3]
    except IndexError:
        output_dir = input_json.parent / f'dumps-{input_json.stem}'
        print(f'Info: <output-dir> not given, using {output_dir}/', file=sys.stderr)
    else:
        output_dir = Path(output_dir_str)
    output_dir.mkdir(exist_ok=True)

    generate_dumps(input_json, output_dir, uniqueness == 'global')

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
