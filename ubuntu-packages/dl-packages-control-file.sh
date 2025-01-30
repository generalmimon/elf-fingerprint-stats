#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

f=ubuntu_dists_noble_main_binary-amd64_Packages.gz
curl -fsSL -o "$f" https://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.gz
gunzip -f -- "$f"

f=ubuntu_dists_noble_main_binary-arm64_Packages.gz
curl -fsSL -o "$f" https://ports.ubuntu.com/dists/noble/main/binary-arm64/Packages.gz
gunzip -f -- "$f"
