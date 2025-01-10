#!/usr/bin/env python3

from collections import defaultdict
from pathlib import Path, PurePosixPath
import shutil
from tarfile import TarInfo
from debian import debfile

script_dir = Path(__file__).parent.resolve(True)
packages_dir = script_dir / 'packages'

elfs_out_dir = script_dir / 'extracted-elfs'
elfs_out_dir.mkdir(exist_ok=True)

num_elfs_written = 0

for deb_path in sorted(packages_dir.glob('*.deb')):
    if not deb_path.is_file():
        continue

    deb_name = deb_path.name

    elf_members_by_name: dict[str, list[TarInfo]] = defaultdict(list)

    with debfile.DebFile(deb_path) as deb:
        with deb.data.tgz() as tar:
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

                    try:
                        o = open(elfs_out_dir / f'{deb_name}-{name}', 'xb')
                    except FileExistsError:
                        continue

                    with tar.extractfile(member) as extracted_file:
                        shutil.copyfileobj(extracted_file, o)
                    num_elfs_written += 1

print(f'{num_elfs_written} ELFs written to {elfs_out_dir}')
