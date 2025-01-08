#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

ubuntu_iso=$(pwd)/ubuntu-24.04.1-live-server-amd64.iso

mkdir -p packages
cd packages

7z e -aoa -r "$ubuntu_iso" 'pool/main/*_amd64.deb'
