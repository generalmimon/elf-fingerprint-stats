#!/usr/bin/env python3

import json
import sys
import textwrap
from collections import Counter
from collections.abc import Iterable
from operator import itemgetter
from pathlib import Path
from typing import Any

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.axes import Axes

UNIQ_CLASSES_AND_LABELS = [
    ('elf_unique', 'ELF-unique'),
    ('binary_pkg_unique', 'Binary package-unique'),
    ('source_pkg_unique', 'Source package-unique'),
    ('not_unique', 'Not unique'),
]

FEAT_TYPE_TO_LABEL = {
    'strings': 'Strings',
    'defined_functions': 'Defined functions',
    'undefined_functions': 'Undefined functions',
    'defined_objects': 'Defined objects',
    'undefined_objects': 'Undefined objects',
    '': 'Other',
}


def read_json(file_path: Path) -> dict[str, Any]:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def reduce_num_features_classified_data_set(full_data_set: dict[str, dict[str, int]], max_num_feature_types: int) -> dict[str, dict[str, int]]:
    assert max_num_feature_types >= 1
    all_feature_types = tuple(full_data_set)
    if len(all_feature_types) > max_num_feature_types:
        feature_types = all_feature_types[:max_num_feature_types - 1]
        data_set = {feat_type: full_data_set[feat_type] for feat_type in feature_types}
        feature_types_set = set(feature_types)
        data_set[''] = {
            uniq_class: sum(
                uniq_class_stats[uniq_class]
                for feat_type, uniq_class_stats in full_data_set.items()
                if feat_type not in feature_types_set
            )
            for uniq_class, _ in UNIQ_CLASSES_AND_LABELS
        }
    else:
        data_set = full_data_set

    return data_set


def plot_num_features_classified_absolute(data_set: dict[str, dict[str, int]], output_filename: Path):
    # See https://matplotlib.org/stable/gallery/lines_bars_and_markers/bar_stacked.html
    data = {
        feat_type: np.array([uniq_class_stats[uniq_class] for uniq_class, _ in UNIQ_CLASSES_AND_LABELS])
        for feat_type, uniq_class_stats in data_set.items()
    }
    uniq_class_labels = [textwrap.fill(label, 14) for _, label in UNIQ_CLASSES_AND_LABELS]

    fig, ax = plt.subplots()
    bottom = np.zeros(len(uniq_class_labels))

    for feat_type, uniq_class_stats in data.items():
        feat_type_label = FEAT_TYPE_TO_LABEL.get(feat_type, feat_type)
        ax.bar(uniq_class_labels, uniq_class_stats, label=feat_type_label, bottom=bottom)
        bottom += uniq_class_stats

    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
    ax.set_title("Number of extracted features from ELFs classified by uniqueness")
    ax.legend(loc='upper right')

    fig.savefig(output_filename)


def plot_num_features_classified_relative(data_set: dict[str, dict[str, int]], output_filename: Path, rotated_xlabels: bool):
    # See https://matplotlib.org/stable/gallery/lines_bars_and_markers/bar_stacked.html
    totals = {
        feat_type: sum(uniq_class_stats[uniq_class] for uniq_class, _ in UNIQ_CLASSES_AND_LABELS)
        for feat_type, uniq_class_stats in data_set.items()
    }

    data = {
        uniq_class: np.array([uniq_class_stats[uniq_class] / totals[feat_type] for feat_type, uniq_class_stats in data_set.items()])
        for uniq_class, _ in UNIQ_CLASSES_AND_LABELS
    }
    feat_type_labels = [FEAT_TYPE_TO_LABEL.get(feat_type, feat_type) for feat_type in data_set.keys()]
    if not rotated_xlabels:
        feat_type_labels = [textwrap.fill(label, 14) for label in feat_type_labels]

    fig, ax = plt.subplots()
    bottom = np.zeros(len(feat_type_labels))
    bars = []

    for uniq_class, uniq_class_label in UNIQ_CLASSES_AND_LABELS:
        d = data[uniq_class]
        bars.append(ax.bar(feat_type_labels, d, label=uniq_class_label, bottom=bottom))
        bottom += d

    ax.bar_label(bars[-1], labels=[f'{totals[feat_type]:,}' for feat_type in data_set.keys()])
    if rotated_xlabels:
        ax.set_xticks(feat_type_labels, feat_type_labels, rotation=30, horizontalalignment='right')

    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.set_title("Ratio of uniqueness classes of extracted features from ELFs")
    ax.legend(loc='lower right')

    if rotated_xlabels:
        fig.tight_layout()
    fig.savefig(output_filename)


def plot_num_strings_by_len_classified(data_set: dict[int, dict[str, int]], output_filename: Path):
    # Basically, we want a histogram like this: https://labwrite.ncsu.edu/res/gh/gh-bargraph.html#histogram

    data = np.array([
        [stats[uniq_class] for uniq_class, _ in UNIQ_CLASSES_AND_LABELS]
        for stats in data_set.values()
    ])

    # See https://stackoverflow.com/a/30305331/12940655
    bins = np.arange(min(data_set.keys()), 100 + 2)
    str_lens = np.clip(list(data_set.keys()), bins[0], bins[-1])
    uniq_class_labels = [label for _, label in UNIQ_CLASSES_AND_LABELS]

    fig, ax = plt.subplots(layout='constrained', figsize=(6, 9))

    ax.hist(
        np.repeat(str_lens[:, np.newaxis], len(UNIQ_CLASSES_AND_LABELS), axis=1),
        bins=bins,
        weights=data,
        histtype='bar',
        orientation='horizontal',
        stacked=True,
        label=uniq_class_labels,
        rwidth=0.8,
    )
    yticks = bins[:-1:2] + 0.5
    ylabels = bins[:-1:2].astype(str)
    ylabels[-1] += '+'
    ax.set_yticks(yticks)
    ax.set_yticklabels(ylabels)
    ax.legend(loc='lower right')
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
    ax.set_title("Number of strings extracted from ELFs grouped by length, classified by uniqueness", wrap=True)

    fig.savefig(output_filename)


def plot_num_features_aggregated_by_num_origins(full_data_sets: dict[str, dict[str, dict[int, int]]], output_filename: Path, max_num_feature_types: int):
    assert max_num_feature_types >= 1
    subplots_info = [
        ('elfs', "grouped by the number of ELFs", "Number of ELFs"),
        ('binary_pkgs', "grouped by the number of binary packages", "Number of binary packages"),
        ('source_pkgs', "grouped by the number of source packages", "Number of source packages"),
    ]

    # Make sure that all datasets have exactly the same feature types (including
    # their order). We rely on this - if this were not true, the resulting chart
    # would be garbage.
    first_data_set_feat_types = tuple(full_data_sets[subplots_info[0][0]])
    if not all(tuple(stats) == first_data_set_feat_types for stats in full_data_sets.values()):
        raise ValueError(f"not all data sets {list(full_data_sets.keys())!r} have keys in the same order, which is required")

    all_feature_types = first_data_set_feat_types
    if len(all_feature_types) > max_num_feature_types:
        feature_types = all_feature_types[:max_num_feature_types - 1]
        data_sets = {
            data_set_key: {feat_type: full_data_set[feat_type] for feat_type in feature_types}
            for data_set_key, full_data_set in full_data_sets.items()
        }
        feature_types_set = set(feature_types)
        for data_set_key, full_data_set in full_data_sets.items():
            others = Counter()
            for feat_type, counter in full_data_set.items():
                if feat_type in feature_types_set:
                    continue
                others += Counter(counter)
            data_sets[data_set_key][''] = {k: v for k, v in sorted(others.items(), key=itemgetter(0))}
    else:
        data_sets = full_data_sets

    feat_type_labels = [FEAT_TYPE_TO_LABEL.get(feat_type, feat_type) for feat_type in data_sets[subplots_info[0][0]]]

    fig, axs = plt.subplots(1, len(subplots_info), layout='constrained', figsize=(15, 6), sharey=True)
    axs: Iterable[Axes]

    for subplot_info, ax in zip(subplots_info, axs, strict=True):
        data_set_key, subplot_title, subplot_xlabel = subplot_info
        data = [
            list(counter.values())
            for counter in data_sets[data_set_key].values()
        ]

        bins = np.arange(1, 5 + 2)
        num_origins = [
            np.clip([int(k) for k in counter], bins[0], bins[-1])
            for counter in data_sets[data_set_key].values()
        ]
        ax.hist(
            num_origins,
            bins=bins,
            weights=data,
            histtype='bar',
            stacked=True,
            label=feat_type_labels,
            rwidth=0.75,
        )
        xlabels = bins[:-1].astype(str)
        xlabels[-1] += '+'
        ax.set_xticks(bins[:-1] + 0.5)
        ax.set_xticklabels(xlabels)
        ax.set_xlabel(subplot_xlabel)

        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
        ax.legend(loc='upper right')
        ax.set_title(subplot_title)

    fig.suptitle("Number of features extracted from ELFs grouped by the number of ELFs/packages in which they occur", wrap=True)

    fig.savefig(output_filename)


def plot_charts(dumps_dir: Path, output_dir: Path) -> None:
    MAX_NUM_FEATURE_TYPES = 8

    aggregated_counts = read_json(dumps_dir / 'classified-aggregated-counts.json')
    reduced_aggregated_counts = reduce_num_features_classified_data_set(aggregated_counts['absolute'], MAX_NUM_FEATURE_TYPES)

    plot_num_features_classified_absolute(
        reduced_aggregated_counts,
        output_dir / 'num-features-classified-absolute.svg',
    )
    ROTATED_XLABELS = True
    plot_num_features_classified_relative(
        reduced_aggregated_counts,
        output_dir / 'num-features-classified-relative.svg',
        ROTATED_XLABELS,
    )
    strings_by_len_orig = read_json(dumps_dir / 'classified-aggregated-strings-by-len-counts.json')
    plot_num_strings_by_len_classified(
        {int(k): v for k, v in strings_by_len_orig.items()},
        output_dir / 'num-strings-by-len-classified.svg',
    )
    features_by_num_origins_orig: dict[str, dict[str, dict[str, int]]] = read_json(dumps_dir / 'aggregated-by-num-origins-counts.json')
    features_by_num_origins = {
        data_set_key: {
            feat_type: {int(k): v for k, v in counter.items()}
            for feat_type, counter in data_set.items()
        }
        for data_set_key, data_set in features_by_num_origins_orig.items()
    }
    plot_num_features_aggregated_by_num_origins(
        features_by_num_origins,
        output_dir / 'num-features-by-num-origins.svg',
        MAX_NUM_FEATURE_TYPES,
    )


def usage(prog_name: str):
    print(f'Usage: {prog_name} <dumps-dir> [<output-dir>]', file=sys.stderr)


def main(argv: list[str]) -> int:
    prog_name = argv[0]
    num_args = len(argv) - 1
    if num_args not in (1, 2):
        print(f'Error: expected 1 or 2 positional arguments, but got {num_args}', file=sys.stderr)
        print(file=sys.stderr)
        usage(prog_name)
        return 1

    dumps_dir = Path(argv[1])
    try:
        output_dir_str = argv[2]
    except IndexError:
        output_dir = dumps_dir.parent / ('charts-' + dumps_dir.name.removeprefix('dumps-'))
        print(f'Info: <output-dir> not given, using {output_dir}/', file=sys.stderr)
    else:
        output_dir = Path(output_dir_str)
    output_dir.mkdir(exist_ok=True)

    # Preserve text as strings in output SVGs, see https://matplotlib.org/stable/users/explain/text/fonts.html#fonts-in-svg
    with plt.rc_context({'svg.fonttype': 'none'}):
        plot_charts(dumps_dir, output_dir)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
