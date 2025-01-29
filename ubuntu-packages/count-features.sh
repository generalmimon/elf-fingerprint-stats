#!/usr/bin/env bash
set -ef

# From https://stackoverflow.com/a/246128
script_dir=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
jq_scripts_dir=$script_dir/jq-scripts

usage_and_exit()
{
    echo
    echo "Usage: $0 <dumps-dir>"
    exit 1
}

if [ "$#" -ne 1 ]; then
    echo "Error: expected 1 positional argument, but got $#" >&2
    usage_and_exit >&2
fi

dumps_dir=$1

if [ -z "$dumps_dir" ]; then
    echo 'Error: <dumps-dir> must not be empty' >&2
    usage_and_exit >&2
fi

dumps_dir=${dumps_dir%/}

declare -p dumps_dir

set -v
jq -f "$jq_scripts_dir"/count-classified-aggregated.jq "$dumps_dir"/classified-aggregated.json > "$dumps_dir"/classified-aggregated-counts.json
jq -f "$jq_scripts_dir"/count-classified-per-elfs.jq "$dumps_dir"/classified-per-elfs.json > "$dumps_dir"/classified-per-elfs-counts.json
jq -f "$jq_scripts_dir"/count-not-unique-grouped-by-elf-set.jq "$dumps_dir"/not-unique-grouped-by-elf-set.json > "$dumps_dir"/not-unique-grouped-by-elf-set-counts.json
