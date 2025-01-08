#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

ubuntu_iso=$(pwd)/ubuntu-24.04.1-live-server-amd64.iso

mkdir -p package-lists
cd package-lists

7z e -aoa "$ubuntu_iso" 'dists/noble/main/binary-amd64/Packages.gz'
7z x -aoa Packages.gz
rm -f Packages.gz
grep -oP '(?<=Package: ).*' Packages > dists-noble-main-amd64.txt
rm -f Packages

7z l "$ubuntu_iso" casper/ > ls-casper.txt

7z e -aoa "$ubuntu_iso" 'casper/install-sources.yaml'

7z e -aoa "$ubuntu_iso" 'casper/filesystem.manifest'
cut -f1 filesystem.manifest > filesystem-packages.txt
