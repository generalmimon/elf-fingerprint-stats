#!/usr/bin/env bash

curl -fLO 'https://releases.ubuntu.com/24.04.1/ubuntu-24.04.1-live-server-amd64.iso'
sha256sum -c -w ubuntu-24.04.1-live-server-amd64.iso.sha256
