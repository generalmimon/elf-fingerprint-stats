#!/usr/bin/env python3

import argparse
import contextlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from operator import itemgetter
from pathlib import Path

import numpy as np
import yara
from sklearn.metrics import classification_report
from sklearn.preprocessing import MultiLabelBinarizer
from tqdm import tqdm

AMD64_IDENTIFIERS_RE = re.compile(r'amd64|x86_64')
ARM64_IDENTIFIERS_RE = re.compile(r'arm64|aarch64')

YARA_ELF_PATH_RE = re.compile(r'\s*name\s*=\s*"(.*)"')

ELF_PATH_REGEX = re.compile(r'(.*)/(.*_\$\{ARCH\}\.deb)-(.*)')

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


def match_yara_rules(yarac_file: str, yara_dir: Path, elfs_dir: Path, log_file: Path | None) -> None:
    yara_elf_name_to_path = defaultdict(list)
    yara_elf_paths = []

    for yara_file in yara_dir.glob('**/*.yara'):
        with open(yara_file, 'r', encoding='utf-8') as f:
            found_name = False
            for line in f:
                m = YARA_ELF_PATH_RE.fullmatch(line.rstrip())
                if m is not None:
                    yara_elf_path_str = m.group(1)
                    found_name = True
                    break
            if not found_name:
                raise ValueError(f"name not found in {yara_file}")

        yara_elf_path_arch_indep = AMD64_IDENTIFIERS_RE.sub('${ARCH}', yara_elf_path_str)
        yara_elf_paths.append(yara_elf_path_arch_indep)

        yara_elf_path = ElfPath.from_str(yara_elf_path_arch_indep)
        yara_elf_name_to_path[yara_elf_path.name].append(yara_elf_path)

    yara_elf_name_to_path: dict[str, list[ElfPath]] = dict(yara_elf_name_to_path)
    yara_elf_paths.sort()

    multilabel_binarizer = MultiLabelBinarizer()
    multilabel_binarizer.fit([yara_elf_paths])

    rules = yara.load(yarac_file)
    elfs = [path for path in elfs_dir.glob('**/*') if path.is_file()]
    elfs.sort()

    expected_elfs_predictions = []
    actual_elfs_predictions = []

    if log_file:
        log_f = open(log_file, 'w', encoding='utf-8')
    else:
        log_f = contextlib.nullcontext()

    with log_f as log_f:
        for elf_path in tqdm(elfs):
            if log_f:
                print(elf_path, file=log_f)
                print('=' * 30, file=log_f)
            rel_elf_path = elf_path.relative_to(elfs_dir)
            elf_path_arch_indep = ARM64_IDENTIFIERS_RE.sub('${ARCH}', str(rel_elf_path))
            elf_path_parsed = ElfPath.from_str(elf_path_arch_indep)
            if elf_path_parsed.name in yara_elf_name_to_path:
                candidates = [
                    yara_elf_path
                    for yara_elf_path in yara_elf_name_to_path[elf_path_parsed.name]
                    if elf_path_parsed.source_pkg == yara_elf_path.source_pkg
                ]
                if len(candidates) > 1:
                    candidates = [
                        yara_elf_path
                        for yara_elf_path in candidates
                        if elf_path_parsed.binary_pkg == yara_elf_path.binary_pkg
                    ]
            else:
                candidates = []

            assert len(candidates) in (0, 1)
            # if len(candidates) == 0:
            #     print(f"{rel_elf_path}: no YARA rule")
            expected_elfs_predictions.append([str(elf_path) for elf_path in candidates])

            actual_elfs_prediction = []

            matching_rules = []
            matches = rules.match(str(elf_path), fast=True)
            for match in matches:
                actual_elfs_prediction.append(AMD64_IDENTIFIERS_RE.sub('${ARCH}', match.meta['name']))

                if log_f:
                    match_score = len(match.strings) / match.meta['total_identifiers']
                    matching_rules.append((match.meta['name'], len(match.strings), match.meta['total_identifiers'], match_score))

            actual_elfs_predictions.append(actual_elfs_prediction)

            if log_f:
                matching_rules.sort(key=itemgetter(-1), reverse=True)
                for rule_id, num_matched, num_total, match_score in matching_rules:
                    print(f"{rule_id} - {num_matched}/{num_total} = {match_score:.1%}", file=log_f)
                print(file=log_f)

    expected_elfs_bin = multilabel_binarizer.transform(expected_elfs_predictions)
    actual_elfs_bin = multilabel_binarizer.transform(actual_elfs_predictions)

    with open('yara-rules-classification-report.log', 'w', encoding='utf-8') as f:
        f.write(
            classification_report(expected_elfs_bin, actual_elfs_bin, output_dict=False, target_names=yara_elf_paths, zero_division=np.nan),
        )
        f.write('\n')
    with open('yara-rules-classification-report.json', 'w', encoding='utf-8') as f:
        json.dump(
            classification_report(expected_elfs_bin, actual_elfs_bin, output_dict=True, target_names=yara_elf_paths, zero_division=np.nan),
            f, ensure_ascii=False, allow_nan=True, indent=2)

    return

def main() -> None:
    parser = argparse.ArgumentParser(description="Match YARA rules against extracted ELFs and calculate evaluation metrics")
    parser.add_argument('elfs_dir', type=Path)
    parser.add_argument('-C', '--yarac', dest='yarac_file', required=True,
                        help="path to a file with compiled YARA rules", metavar='YARAC_FILE')
    parser.add_argument('-y', '--yara-dir', dest='yara_dir', type=Path, required=True,
                        help="directory with YARA rules", metavar='DIR')
    parser.add_argument('-l', '--log', dest='log_file', type=Path, required=False,
                        help="log file", metavar='LOG')
    args = parser.parse_args()

    match_yara_rules(args.yarac_file, args.yara_dir, args.elfs_dir, args.log_file)

if __name__ == '__main__':
    main()
