#!/usr/bin/env python3

from pathlib import Path, PurePosixPath
import requests  # If this fails, make sure to [install Requests](https://requests.readthedocs.io/en/latest/user/install/)
import sys
import re
import gzip
from dataclasses import dataclass
from debian import deb822

script_dir = Path(__file__).parent.resolve(True)
packages_out_dir = script_dir / 'packages'
packages_out_dir.mkdir(exist_ok=True)

def usage(argv):
    return f'Usage: {argv[0]} ( <mirror_url> | -h | --help )'

if len(sys.argv) != 2:
    print(usage(sys.argv), file=sys.stderr)
    sys.exit(1)

if sys.argv[1] in ('-h', '--help'):
    print(usage(sys.argv))
    sys.exit()

mirror_url = sys.argv[1]
mirror_url = mirror_url.removesuffix('/')

# See <https://www.debian.org/doc/debian-policy/ch-controlfields.html#source>:
# Package names (both source and binary, see Package) must consist only of lower case letters (a-z), digits
# (0-9), plus (+) and minus (-) signs, and periods (.). They must be at least two characters long and must start
# with an alphanumeric character.
DEB_PACKAGE_NAME_REGEX = re.compile(r'[a-z][a-z0-9+\-.]+')

def get_packages_control_file_contents(mirror_url):
    r = requests.get(f'{mirror_url}/ubuntu/dists/noble/main/binary-amd64/Packages.gz')
    r.raise_for_status()
    assert r.headers['content-type'] in ('application/gzip', 'application/x-gzip')
    return gzip.decompress(r.content)

@dataclass
class Package:
    name: str
    version: str
    filename: str
    architecture: str

def download_packages_in_manifest(manifest_path: Path, packages: dict[str, Package], packages_out_dir: Path):
    with open(manifest_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            name, version = line.split('\t', maxsplit=1)
            if name.startswith('snap:'):
                continue

            if name.endswith(':amd64'):
                name = name.removesuffix(':amd64')

            if DEB_PACKAGE_NAME_REGEX.fullmatch(name) is None:
                print(f'{name!r} is invalid')

            try:
                pkg = packages[name]
            except KeyError:
                print(f'package {name!r} not found')
                continue

            pkg_basename = PurePosixPath(pkg.filename).name

            if pkg.architecture != 'amd64':
                continue

            try:
                o = open(packages_out_dir / pkg_basename, 'xb')
            except FileExistsError:
                continue

            with o:
                # https://stackoverflow.com/a/16696317/12940655
                with requests.get(f'{mirror_url}/ubuntu/{pkg.filename}', stream=True) as r:
                    print(r.url)
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=8192):
                        o.write(chunk)


packages_file_contents = get_packages_control_file_contents(mirror_url)

packages: dict[str, Package] = {}
for pkg in deb822.Packages.iter_paragraphs(packages_file_contents, use_apt_pkg=False):
    name = pkg['package']
    packages[name] = Package(name, pkg['version'], pkg['filename'], pkg['architecture'])

download_packages_in_manifest(script_dir / 'ubuntu-24.04.1-desktop-amd64.manifest', packages, packages_out_dir)
download_packages_in_manifest(script_dir / 'ubuntu-24.04.1-live-server-amd64.manifest', packages, packages_out_dir)
