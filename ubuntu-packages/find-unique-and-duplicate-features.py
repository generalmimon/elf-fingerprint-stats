#!/usr/bin/env python3

from collections import defaultdict
import copy
from dataclasses import dataclass
import json
from operator import itemgetter
from pathlib import Path
import re
import uuid

script_dir = Path(__file__).parent.resolve(True)
strings_dir = script_dir / 'extracted-strings'

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

# Adapted from https://stackoverflow.com/a/25935321/12940655
class NoIndent:
    def __init__(self, value):
        self.value = value

# Adapted from https://stackoverflow.com/a/25935321/12940655
class NoIndentEncoder(json.JSONEncoder):
    def __init__(self, *args, **kwargs):
        super(NoIndentEncoder, self).__init__(*args, **kwargs)
        self.kwargs = dict(kwargs)
        del self.kwargs['indent']
        self._replacement_map = {}

    def _do_replacement_on_part(self, part: str):
        if part.startswith('"@@'):
            try:
                return self._replacement_map[part[3:-3]]
            except KeyError:
                return part
        else:
            return part

    def default(self, o):
        if isinstance(o, NoIndent):
            key = uuid.uuid4().hex
            self._replacement_map[key] = json.dumps(o.value, **self.kwargs)
            return "@@%s@@" % (key,)
        else:
            return super().default(o)

    def iterencode(self, o, _one_shot = False):
        parts = super().iterencode(o, _one_shot)
        return map(self._do_replacement_on_part, parts)

def read_from_elfs_json(json_path: Path) -> dict[ElfPath, dict[str, list[str]]]:
    with open(json_path, 'r', encoding='utf-8') as f:
        orig_json = json.load(f)
        return {ElfPath.from_str(elf_path_str): features_dict for elf_path_str, features_dict in orig_json.items()}

def main():
    json_from_elfs = read_from_elfs_json(strings_dir / 'from-elfs.json')

    inverse_map: dict[str, dict[str, list[ElfPath]]] = defaultdict(lambda: defaultdict(list))
    for elf_path, features_dict in json_from_elfs.items():
        for feature_type, instances in features_dict.items():
            pool = inverse_map[feature_type]
            processed_instances = set()
            for inst in instances:
                if inst in processed_instances:
                    continue
                pool[inst].append(elf_path)
                processed_instances.add(inst)

    features_dict_template = {feature_type: [] for feature_type in inverse_map}

    grouped_by_elf_set = defaultdict(lambda: copy.deepcopy(features_dict_template))

    FEATURE_GROUPS = ['elf_unique', 'binary_pkg_unique', 'source_pkg_unique', 'not_unique']
    elf_info_template = {feat_group: copy.deepcopy(features_dict_template) for feat_group in FEATURE_GROUPS}

    packages_info = defaultdict(dict)
    for elf_path in json_from_elfs:
        packages_info[elf_path.pkg_path][elf_path.name] = copy.deepcopy(elf_info_template)

    packages_info = dict(packages_info)
    aggr_features = {feat_group: copy.deepcopy(features_dict_template) for feat_group in FEATURE_GROUPS}

    for feature_type, instances_dict in inverse_map.items():
        for inst, elfs in instances_dict.items():
            num_elfs = len(elfs)
            num_binary_pkgs = len(set(elf_path.binary_pkg for elf_path in elfs))
            num_source_pkgs = len(set(elf_path.source_pkg for elf_path in elfs))
            if num_elfs == 1:
                feat_group = 'elf_unique'
            elif num_binary_pkgs == 1:
                feat_group = 'binary_pkg_unique'
            elif num_source_pkgs == 1:
                feat_group = 'source_pkg_unique'
            else:
                feat_group = 'not_unique'
                grouped_by_elf_set[tuple(elfs)][feature_type].append(inst)
            for elf_path in elfs:
                packages_info[elf_path.pkg_path][elf_path.name][feat_group][feature_type].append(inst)
            aggr_features[feat_group][feature_type].append((inst, (num_source_pkgs, num_binary_pkgs, num_elfs)))

    ordered_aggr_features = {
        feat_group: {
            feature_type: {tup[0]: NoIndent(tup[1]) for tup in sorted(instances, key=itemgetter(1), reverse=True)}
            for feature_type, instances in features_dict.items()
        }
        for feat_group, features_dict in aggr_features.items()
    }

    ordered_grouped_by_elf_set = [
        {'elfs': list(map(str, elf_paths)), **features_dict}
        for elf_paths, features_dict in sorted(grouped_by_elf_set.items(), key=lambda t: sum(len(instances) for instances in t[1].values()), reverse=True)
    ]

    with open(strings_dir / 'from-elfs-classified-aggregated.json', 'w', encoding='utf-8') as f:
        comment = 'The meaning of the numbers is [num_source_pkgs, num_binary_pkgs, num_elfs]'
        json.dump({'$comment': comment, **ordered_aggr_features}, f, ensure_ascii=False, allow_nan=False, indent=2, cls=NoIndentEncoder)

    with open(strings_dir / 'from-elfs-classified-per-packages.json', 'w', encoding='utf-8') as f:
        json.dump(packages_info, f, ensure_ascii=False, allow_nan=False, indent=2)

    with open(strings_dir / 'from-elfs-duplicate-grouped.json', 'w', encoding='utf-8') as f:
        json.dump(ordered_grouped_by_elf_set, f, ensure_ascii=False, allow_nan=False, indent=2)


if __name__ == '__main__':
    main()
