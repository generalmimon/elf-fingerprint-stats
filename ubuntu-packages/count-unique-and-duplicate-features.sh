#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

jq -f count-classified-per-packages.jq extracted-strings/from-elfs-classified-per-packages.json > extracted-strings/from-elfs-classified-per-packages-counts.json
jq -f count-duplicate-grouped.jq extracted-strings/from-elfs-duplicate-grouped.json > extracted-strings/from-elfs-duplicate-grouped-counts.json
