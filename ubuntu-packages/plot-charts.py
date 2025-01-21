#!/usr/bin/env python3

import json
from pathlib import Path
import textwrap
from typing import Any
import matplotlib
import matplotlib.pyplot as plt
import numpy as np


script_dir = Path(__file__).parent.resolve(True)
strings_dir = script_dir / 'extracted-strings'
charts_dir = strings_dir / 'charts'
charts_dir.mkdir(exist_ok=True)

UNIQ_CLASSES_AND_LABELS = [
    ('elf_unique', 'ELF-unique'),
    ('binary_pkg_unique', 'Binary package-unique'),
    ('source_pkg_unique', 'Source package-unique'),
    ('not_unique', 'Not unique'),
]

FEAT_TYPES_AND_LABELS = [
    ('strings', 'Strings'),
    ('defined_functions', 'Defined functions'),
    ('undefined_functions', 'Undefined functions'),
    ('defined_objects', 'Defined objects'),
    ('undefined_objects', 'Undefined objects'),
]


def read_json_with_int_keys(file_path: Path) -> dict[int, Any]:
    with open(file_path, 'r', encoding='utf-8') as f:
        orig_dict = json.load(f)
        return {int(k): v for k, v in orig_dict.items()}


def plot_num_features_classified_absolute(data_set: dict[str, dict[str, int]], output_filename: Path):
    # See https://matplotlib.org/stable/gallery/lines_bars_and_markers/bar_stacked.html
    data = {
        feat_type: np.array([data_set[feat_type][uniq_class] for uniq_class, _ in UNIQ_CLASSES_AND_LABELS])
        for feat_type, _ in FEAT_TYPES_AND_LABELS
    }
    uniq_class_labels = [textwrap.fill(label, 14) for _, label in UNIQ_CLASSES_AND_LABELS]

    fig, ax = plt.subplots()
    bottom = np.zeros(len(uniq_class_labels))

    for feat_type, feat_type_label in FEAT_TYPES_AND_LABELS:
        d = data[feat_type]
        ax.bar(uniq_class_labels, d, label=feat_type_label, bottom=bottom)
        bottom += d

    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
    ax.set_title("Number of extracted features from ELFs classified by uniqueness")
    ax.legend(loc='upper right')

    fig.savefig(output_filename)


def plot_num_features_classified_relative(data_set: dict[str, dict[str, float]], totals: dict[str, int], output_filename: Path):
    # See https://matplotlib.org/stable/gallery/lines_bars_and_markers/bar_stacked.html
    data = {
        uniq_class: np.array([data_set[feat_type][uniq_class] for feat_type, _ in FEAT_TYPES_AND_LABELS])
        for uniq_class, _ in UNIQ_CLASSES_AND_LABELS
    }
    feat_type_labels = [textwrap.fill(label, 14) for _, label in FEAT_TYPES_AND_LABELS]

    fig, ax = plt.subplots()
    bottom = np.zeros(len(feat_type_labels))
    bars = []

    for uniq_class, uniq_class_label in UNIQ_CLASSES_AND_LABELS:
        d = data[uniq_class]
        bars.append(ax.bar(feat_type_labels, d, label=uniq_class_label, bottom=bottom))
        bottom += d

    ax.bar_label(bars[-1], labels=[f'{totals[feat_type]:,}' for feat_type, _ in FEAT_TYPES_AND_LABELS])

    ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.set_title("Ratio of uniqueness classes of extracted features from ELFs")
    ax.legend(loc='lower right')

    fig.savefig(output_filename)


def plot_num_strings_by_len_classified(data_set: dict[int, dict[str, int]], output_filename: Path):
    # Basically, we want a histogram like this: https://labwrite.ncsu.edu/res/gh/gh-bargraph.html#histogram

    data = np.array([
        [stats[uniq_class] for uniq_class, _ in UNIQ_CLASSES_AND_LABELS]
        for stats in data_set.values()
    ])

    # See https://stackoverflow.com/a/30305331/12940655
    step = 2
    bins = np.arange(min(data_set.keys()), 100 + step + 1, step)
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
    )
    ylabels = bins.astype(str)
    ylabels[-1] = max(data_set.keys())
    ax.set_yticks(bins)
    ax.set_yticklabels(ylabels)
    ax.legend(loc='lower right')
    ax.invert_yaxis()
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
    ax.set_title("Number of strings extracted from ELFs grouped by length and classified by uniqueness", wrap=True)

    fig.savefig(output_filename)


def main():
    with open(strings_dir / 'from-elfs-classified-aggregated-counts.json', 'r', encoding='utf-8') as f:
        aggregated_counts = json.load(f)

    plot_num_features_classified_absolute(
        aggregated_counts['absolute'],
        charts_dir / 'from-elfs-num-features-classified-absolute.svg'
    )
    plot_num_features_classified_relative(
        aggregated_counts['relative'],
        {feat_type: stats['total'] for feat_type, stats in aggregated_counts['absolute'].items()},
        charts_dir / 'from-elfs-num-features-classified-relative.svg'
    )
    plot_num_strings_by_len_classified(
        read_json_with_int_keys(strings_dir / 'from-elfs-classified-aggregated-strings-by-len-counts.json'),
        charts_dir / 'from-elfs-num-strings-by-len-classified.svg'
    )


if __name__ == '__main__':
    # Preserve text as strings in output SVGs, see https://matplotlib.org/stable/users/explain/text/fonts.html#fonts-in-svg
    with plt.rc_context({'svg.fonttype': 'none'}):
        main()
