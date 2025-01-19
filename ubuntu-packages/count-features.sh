#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

jq -f jq-scripts/count-classified-aggregated.jq extracted-strings/from-elfs-classified-aggregated.json > extracted-strings/from-elfs-classified-aggregated-counts.json
jq -f jq-scripts/count-classified-per-packages.jq extracted-strings/from-elfs-classified-per-packages.json > extracted-strings/from-elfs-classified-per-packages-counts.json
jq -f jq-scripts/count-duplicate-grouped.jq extracted-strings/from-elfs-duplicate-grouped.json > extracted-strings/from-elfs-duplicate-grouped-counts.json
