#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

if [[ $(kaitai-struct-compiler --version) == 'kaitai-struct-compiler 0.10' ]]; then
    ksc_bin=kaitai-struct-compiler
elif [[ $(kaitai-struct-compiler-0.10 --version) == 'kaitai-struct-compiler 0.10' ]]; then
    ksc_bin=kaitai-struct-compiler-0.10
else
    echo 'KSC 0.10 not found' >&2
    exit 1
fi

"$ksc_bin" -- -t python elf.ksy
