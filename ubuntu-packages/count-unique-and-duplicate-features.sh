#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

jq --indent 4 -f count-unique-per-packages.jq extracted-strings/from-elfs-unique-per-packages.json > extracted-strings/from-elfs-unique-per-packages-counts.json
jq --indent 4 -f count-duplicate-grouped.jq extracted-strings/from-elfs-duplicate-grouped.json > extracted-strings/from-elfs-duplicate-grouped-counts.json
