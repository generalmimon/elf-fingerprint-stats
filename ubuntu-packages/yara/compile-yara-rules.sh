#!/usr/bin/env bash
set -e

usage()
{
    echo "Usage: $0 <rules-dir> <output-file>" >&2
}

if [ "$#" -ne 2 ]; then
    usage
    echo >&2
    echo "Error: expected 2 positional arguments, but got $#" >&2
    exit 1
fi

rules_dir=$1

if [ -z "$rules_dir" ]; then
    usage
    echo >&2
    echo 'Error: <rules-dir> must not be empty' >&2
    exit 1
fi

rules_dir=${rules_dir%/}

output_file=$2

if [ -z "$output_file" ]; then
    usage
    echo >&2
    echo 'Error: <output-file> must not be empty' >&2
    exit 1
fi

time -p yarac --fail-on-warnings --strict-escape "$rules_dir"/*.yara "$output_file"
