#!/usr/bin/env python3

import shutil
from collections import defaultdict
from pathlib import Path, PurePosixPath
from tarfile import TarInfo

from debian import debfile
from tqdm import tqdm

script_dir = Path(__file__).parent.resolve(True)
packages_dir = script_dir / 'packages'

elfs_out_dir = script_dir / 'extracted-elfs'
elfs_out_dir.mkdir(exist_ok=True)

num_elfs_written = 0

for deb_path in tqdm(sorted(packages_dir.glob('**/*.deb'))):
    if not deb_path.is_file():
        continue

    deb_name = deb_path.name
    rel_deb_path = deb_path.relative_to(packages_dir)
    rel_deb_dir = rel_deb_path.parent

    with debfile.DebFile(deb_path) as deb:
        with deb.data.tgz() as tar:
            elf_members_by_name: dict[str, list[TarInfo]] = defaultdict(list)
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                with tar.extractfile(member) as extracted_file:
                    if extracted_file.read(4) != b'\x7fELF':
                        continue

                member_path = PurePosixPath(member.name)
                elf_members_by_name[member_path.name].append(member)

            for bin_name, elf_members in elf_members_by_name.items():
                only_basename = len(elf_members) == 1
                for member in elf_members:
                    member_path = PurePosixPath(member.name)
                    name = member_path.name if only_basename else '-'.join(member_path.parts)

                    source_pkg_dir = elfs_out_dir / rel_deb_dir
                    source_pkg_dir.mkdir(parents=True, exist_ok=True)
                    try:
                        o = open(source_pkg_dir / f'{deb_name}-{name}', 'xb')
                    except FileExistsError:
                        continue

                    with tar.extractfile(member) as extracted_file:
                        shutil.copyfileobj(extracted_file, o)
                    num_elfs_written += 1

print(f'{num_elfs_written} ELFs written to {elfs_out_dir}')
