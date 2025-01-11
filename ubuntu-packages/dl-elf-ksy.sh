#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

curl -fsSLO https://github.com/armijnhemel/binaryanalysis-ng/raw/e05071e01213c7d7d7261e979ab1d308872e87d0/src/bang/parsers/executable/elf/elf.ksy
