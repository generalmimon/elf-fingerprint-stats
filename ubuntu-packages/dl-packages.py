#!/usr/bin/env python3

import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import requests
from debian import deb822

# See <https://www.debian.org/doc/debian-policy/ch-controlfields.html#source>:
# Package names (both source and binary, see Package) must consist only of lower case letters (a-z), digits
# (0-9), plus (+) and minus (-) signs, and periods (.). They must be at least two characters long and must start
# with an alphanumeric character.
DEB_PACKAGE_NAME_REGEX = re.compile(r'[a-z][a-z0-9+\-.]+')

@dataclass
class Package:
    name: str
    version: str
    filename: PurePosixPath
    architecture: str
    source: str

def download_packages_in_manifest(manifest_path: Path, packages: dict[str, Package], packages_out_dir: Path, mirror_url: str):
    with open(manifest_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            name, version = line.split('\t', maxsplit=1)
            if name.startswith('snap:'):
                continue

            if name.endswith(':amd64'):
                name = name.removesuffix(':amd64')
            elif name.endswith(':arm64'):
                name = name.removesuffix(':arm64')

            if DEB_PACKAGE_NAME_REGEX.fullmatch(name) is None:
                raise ValueError(f'invalid package name {name!r}')

            try:
                pkg = packages[name]
            except KeyError:
                print(f'package {name!r} not found')
                continue

            pkg_basename = PurePosixPath(pkg.filename).name

            if pkg.architecture not in ('amd64', 'arm64'):
                continue

            source_pkg_dir = packages_out_dir / pkg.source
            source_pkg_dir.mkdir(exist_ok=True)

            try:
                o = open(source_pkg_dir / pkg_basename, 'xb')
            except FileExistsError:
                continue

            with o:
                # https://stackoverflow.com/a/16696317/12940655
                with requests.get(f'{mirror_url}/{pkg.filename}', stream=True) as r:
                    print(r.url)
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=8192):
                        o.write(chunk)


def dl_packages(arch: str, script_dir: Path, packages_out_dir: Path, mirror_url: str) -> None:
    if arch == 'amd64':
        packages_control_file_name = 'ubuntu_dists_noble_main_binary-amd64_Packages'
    elif arch == 'arm64':
        packages_control_file_name = 'ubuntu_dists_noble_main_binary-arm64_Packages'

    with open(script_dir / packages_control_file_name, 'rb') as packages_file:
        packages: dict[str, Package] = {}
        for pkg in deb822.Packages.iter_paragraphs(packages_file, use_apt_pkg=False):
            name = pkg['package']
            filename = PurePosixPath(pkg['filename'])
            assert pkg.source == filename.parent.name
            packages[name] = Package(name, pkg['version'], filename, pkg['architecture'], pkg.source)

    if arch == 'amd64':
        download_packages_in_manifest(script_dir / 'ubuntu-24.04.1-desktop-amd64.manifest', packages, packages_out_dir, mirror_url)
        download_packages_in_manifest(script_dir / 'ubuntu-24.04.1-live-server-amd64.manifest', packages, packages_out_dir, mirror_url)
    elif arch == 'arm64':
        download_packages_in_manifest(script_dir / 'ubuntu-24.04.1-preinstalled-desktop-arm64+raspi.manifest', packages, packages_out_dir, mirror_url)
        download_packages_in_manifest(script_dir / 'ubuntu-24.04.1-live-server-arm64.manifest', packages, packages_out_dir, mirror_url)


def usage(argv: list[str]) -> str:
    return f'Usage: {argv[0]} ( <mirror_url> <arch> | -h | --help )'

def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] in ('-h', '--help'):
        print(usage(argv))
        return 0

    if len(argv) != 3:
        print(usage(argv), file=sys.stderr)
        return 1

    mirror_url = argv[1]
    mirror_url = mirror_url.removesuffix('/')

    arch = argv[2]
    if arch not in ('amd64', 'arm64'):
        print(f"Error: <arch> must be 'amd64' or 'arm64', but got {arch!r}", file=sys.stderr)
        return 1

    if arch == 'amd64' and not mirror_url.endswith('/ubuntu'):
        mirror_url += '/ubuntu'

    script_dir = Path(__file__).parent.resolve(True)
    packages_out_dir = script_dir / f'packages-{arch}'
    packages_out_dir.mkdir(exist_ok=True)

    dl_packages(arch, script_dir, packages_out_dir, mirror_url)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
