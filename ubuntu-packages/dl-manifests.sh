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
