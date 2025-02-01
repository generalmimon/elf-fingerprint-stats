#!/usr/bin/env python3

import argparse
import itertools
import json
import random
import re
from pathlib import Path, PurePosixPath
from typing import Any

from yara_config import YaraConfig


def read_json(file_path: Path) -> dict[str, Any]:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# Extracted from BANG: https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/maintenance/yara/yara_from_bang.py#L41-L48
# YARA escape sequences
ESCAPE = str.maketrans({'"': '\\"',
                        '\\': '\\\\',
                        '\t': '\\t',
                        '\n': '\\n'})

INVALID_IDENT_CHAR_RE = re.compile(r'[^A-Za-z0-9_]')


def translate_string_for_yara(s: str) -> str:
    translated_s = s.translate(ESCAPE)
    return f'"{translated_s}"'


def elf_path_to_rule_id(elf_path: str) -> str:
    elf_name = PurePosixPath(elf_path).name
    elf_name_as_id = INVALID_IDENT_CHAR_RE.sub('_', elf_name)
    return elf_name_as_id


# Extracted from BANG: https://github.com/armijnhemel/binaryanalysis-ng/blob/e05071e01213c7d7d7261e979ab1d308872e87d0/maintenance/yara/yara_from_bang.py#L51-L135
def generate_yara(rule_id, yara_file, metadata, functions, variables, strings,
                  tags, num_strings, num_funcs, num_vars, fullword,
                  yara_operator, identifiers_from) -> None:
    '''Generate YARA rules from identifiers.'''
    total_identifiers = len(functions) + len(variables) + len(strings)
    meta = f'''
    meta:
        description = "Rule for {metadata['name']}"
        total_identifiers = {total_identifiers}
        identifiers_from = {translate_string_for_yara(identifiers_from)}
'''

    for m in sorted(metadata):
        meta += f'        {m} = {translate_string_for_yara(metadata[m])}\n'

    # create a tags string for the rule if there are any tags.
    # These can be used by YARA to only run specific rules.
    tags_string = ''
    if tags != []:
        tags_string = ": " + " ".join(tags)

    rule_name = f'rule {rule_id}{tags_string}\n'

    with yara_file.open(mode='w') as p:
        p.write(rule_name)
        p.write('{')
        p.write(meta)
        p.write('\n    strings:\n')

        # First write all strings
        if strings != []:
            p.write("\n        // Extracted strings\n\n")
            for counter, s_raw in enumerate(strings, 1):
                s = translate_string_for_yara(s_raw)
                p.write(f"        $string{counter} = {s}{fullword}\n")

        # Then write the functions
        if functions != []:
            p.write("\n        // Extracted functions\n\n")
            counter = 1
            for counter, s_raw in enumerate(functions, 1):
                s = translate_string_for_yara(s_raw)
                p.write(f"        $function{counter} = {s}{fullword}\n")

        # Then the variable names
        if variables != []:
            p.write("\n        // Extracted variables\n\n")
            for counter, s_raw in enumerate(variables, 1):
                s = translate_string_for_yara(s_raw)
                p.write(f"        $variable{counter} = {s}{fullword}\n")

        # Finally write the conditions
        p.write('\n    condition:\n')
        if strings != []:
            p.write(f'        {num_strings} of ($string*)')

            if not (functions == [] and variables == []):
                p.write(f' {yara_operator}\n')
            else:
                p.write('\n')
        if functions != []:
            p.write(f'        {num_funcs} of ($function*)')

            if variables != []:
                p.write(' %s\n' % yara_operator)
            else:
                p.write('\n')
        if variables != []:
            p.write(f'        {num_vars} of ($variable*)')
        p.write('\n}\n')

    # # return the UUID for the rule so it can be recorded
    # return rule_uuid


def binary(rule_id: str, metadata: dict[str, str], features_dict: dict[str, list[str]], yara_env: dict[str, Any], yara_directory: Path,
           no_strings: bool, no_functions: bool, no_variables: bool, identifiers_from: str):

    strings = set()
    functions = set()
    variables = set()

    heuristics = yara_env['heuristics']

    # lq_identifiers = {
    #     'elf': {
    #         'strings': {
    #             '.text',
    #             '.data',
    #             '.data.rel.ro',
    #             '.bss',
    #             '.rodata',
    #             '.dynstr',
    #             '.dynamic',
    #             '.eh_frame',
    #             '.eh_frame_hdr',
    #             '.fini_array',
    #             '.interp',
    #             '.init',
    #             '.fini',
    #             '.init_array',
    #             '.fini_array',
    #             '.gnu.hash',
    #             '.gnu.version',
    #             '.gnu.version',
    #             '.gnu.version',
    #             '.gnu.version_r',
    #             '.gnu_debuglink',
    #             '.gnu_debugaltlink',
    #             '.note.gnu.build-id',
    #             '.note.gnu.property',
    #             '.note.ABI-tag',
    #             '.rela.dyn',
    #             '.rela.plt',
    #             '.plt.got',
    #             '.plt.sec',
    #             '.shstrtab',
    #             '_ITM_deregisterTMCloneTable',
    #             '_ITM_registerTMCloneTable',
    #             '__cxa_finalize',
    #             '__gmon_start__',
    #         },
    #     },
    # }

    # process strings
    if not no_strings:
        for s in features_dict['strings']:
            if len(s) < yara_env['string_minimum_length']:
                continue
            if len(s) > yara_env['string_maximum_length']:
                continue
            # ignore whitespace-only strings
            if s.isspace():
                continue
            # if s in lq_identifiers['elf']['strings']:
            #     continue
            strings.add(s)

    # process symbols, split in functions and variables
    if not no_functions:
        for s in features_dict['defined_functions']:
            if len(s) < yara_env['identifier_cutoff']:
                continue
            functions.add(s)

    if not no_variables:
        for s in features_dict['defined_objects']:
            if len(s) < yara_env['identifier_cutoff']:
                continue
            variables.add(s)

    # for s in bang_data['symbols']:
    #     # if s['section_index'] == 0:
    #     #     continue
    #     # if yara_env['ignore_weak_symbols']:
    #     #     if s['binding'] == 'weak':
    #     #         continue
    #     if len(s['name']) < yara_env['identifier_cutoff']:
    #         continue
    #     # if '@@' in s['name']:
    #     #     identifier_name = s['name'].rsplit('@@', 1)[0]
    #     # elif '@' in s['name']:
    #     #     identifier_name = s['name'].rsplit('@', 1)[0]
    #     # else:
    #     identifier_name = s['name']
    #     if s['type'] == 'func' and not no_functions:
    #         if identifier_name in lq_identifiers['elf']['functions']:
    #             continue
    #         functions.add(identifier_name)
    #     elif s['type'] == 'object' and not no_variables:
    #         if identifier_name in lq_identifiers['elf']['variables']:
    #             continue
    #         variables.add(identifier_name)

    # do not generate a YARA file if there is no data
    if \
        (
            len(strings) < heuristics['strings_extracted'] and
            len(functions) < heuristics['functions_extracted'] and
            len(variables) < heuristics['variables_extracted']
        ):
        print(f"{metadata['name']}: not generating a YARA rule - only {len(strings)} strings, {len(functions)} functions and {len(variables)} variables")
        return

    # check if the number of identifiers passes a threshold.
    # If not assume that there are no identifiers.
    if len(strings) < heuristics['strings_extracted']:
        strings = set()
    if len(functions) < heuristics['functions_extracted']:
        functions = set()
    if len(variables) < heuristics['variables_extracted']:
        variables = set()

    # yara_tags = sorted(set(tags + [exec_type]))
    yara_tags = []

    total_identifiers = len(functions) + len(variables) + len(strings)

    # by default YARA has a limit of 10,000 identifiers
    # TODO: see which ones can be ignored.
    if total_identifiers > yara_env['max_identifiers']:
        over_limit = total_identifiers - yara_env['max_identifiers']
        if len(strings) - over_limit >= 4000:
            strings = random.sample(list(strings), k=len(strings) - over_limit)
        elif len(functions) - over_limit >= 4000:
            functions = random.sample(list(functions), k=len(functions) - over_limit)
        else:
            if len(strings) > 4000:
                over_limit -= len(strings) - 4000
                strings = random.sample(list(strings), k=4000)
            if len(functions) - over_limit >= 2500:
                functions = random.sample(list(functions), k=len(functions) - over_limit)
            else:
                print(f"{metadata['name']}: number of identifiers {total_identifiers} ({len(strings)} strings, {len(functions)} functions and {len(variables)} variables) exceeds limit of {yara_env['max_identifiers']}")
                return

    yara_file = yara_directory / f'{rule_id}.yara'

    fullword = ''
    if yara_env['fullword']:
        fullword = ' fullword'

    num_strings = num_funcs = num_vars = 'any'

    if len(strings) >= heuristics['strings_minimum_present']:
        # num_strings = str(int(max(len(strings)//heuristics['strings_percentage'], heuristics['strings_matched'])))
        num_strings = int(max(len(strings) * (heuristics['strings_percentage'] / 100), heuristics['strings_matched']))

    if len(functions) >= heuristics['functions_minimum_present']:
        # num_funcs = str(int(max(len(functions)//heuristics['functions_percentage'], heuristics['functions_matched'])))
        num_funcs = int(max(len(functions) * (heuristics['functions_percentage'] / 100), heuristics['functions_matched']))

    if len(variables) >= heuristics['variables_minimum_present']:
        # num_vars = str(int(max(len(variables)//heuristics['variables_percentage'], heuristics['variables_matched'])))
        num_vars = int(max(len(variables) * (heuristics['variables_percentage'] / 100), heuristics['variables_matched']))

    generate_yara(rule_id, yara_file, metadata, sorted(functions), sorted(variables),
                  sorted(strings), yara_tags, num_strings, num_funcs, num_vars,
                  fullword, yara_env['operator'], identifiers_from)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate YARA rules from extracted strings")
    parser.add_argument('-d', '--outdir', required=True, dest='output_dir', type=Path,
                        help="output directory for generated YARA rules", metavar='DIR')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--from-elfs', dest='from_elfs', type=Path,
                        help="from-elfs.json file with extracted strings", metavar='JSON_FILE')
    group.add_argument('-b', '--from-blobs', dest='from_blobs', type=Path,
                        help="from-blobs.json file with extracted strings", metavar='JSON_FILE')
    args = parser.parse_args()

    script_dir = Path(__file__).parent.resolve(True)
    with open(script_dir / 'yara-config.yaml', 'r', encoding='utf-8') as config_file:
        yara_config = YaraConfig(config_file)

    # parse the configuration
    yara_env = yara_config.parse()

    output_dir = args.output_dir
    output_dir.mkdir(exist_ok=True)

    if args.from_elfs is not None:
        src_file = args.from_elfs
        elf_to_features: dict[str, dict[str, list[str]]] = read_json(src_file)
    else:
        src_file = args.from_blobs
        elf_to_features: dict[str, dict[str, list[str]]] = read_json(args.from_blobs)
        elf_to_features = {
            elf_path: {
                'strings': list(itertools.chain.from_iterable(features_dict.values())),
                'defined_functions': [],
                'defined_objects': [],
            }
            for elf_path, features_dict in elf_to_features.items()
        }

    identifiers_from = str(src_file)
    rule_id_to_elf_path = {}

    for elf_path, features_dict in elf_to_features.items():
        rule_id = elf_path_to_rule_id(elf_path)
        if rule_id in rule_id_to_elf_path:
            raise ValueError(f"failed to generate a unique rule ID for {elf_path} ({rule_id} already assigned to {rule_id_to_elf_path[rule_id]})")
        rule_id_to_elf_path[rule_id] = elf_path
        binary(rule_id, {'name': elf_path}, features_dict, yara_env, output_dir, False, False, False, identifiers_from)

    return 0


if __name__ == '__main__':
    main()
