#!/usr/bin/env bash
set -ef

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null

dl_manifest()
{
    (
        set -x
        curl -fsSLO --url "$1"
    )
}

dl_manifest https://releases.ubuntu.com/noble/ubuntu-24.04.1-desktop-amd64.manifest
dl_manifest https://releases.ubuntu.com/noble/ubuntu-24.04.1-live-server-amd64.manifest
dl_manifest 'https://cdimage.ubuntu.com/releases/noble/release/ubuntu-24.04.1-live-server-arm64.manifest'
dl_manifest 'https://cdimage.ubuntu.com/releases/noble/release/ubuntu-24.04.1-preinstalled-desktop-arm64+raspi.manifest'
sed -i "s| |$(printf '\t')|" 'ubuntu-24.04.1-preinstalled-desktop-arm64+raspi.manifest'
