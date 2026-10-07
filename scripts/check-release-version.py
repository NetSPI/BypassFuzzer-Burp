#!/usr/bin/env python3
"""Prevent publishing an artifact whose embedded version disagrees with its release tag."""
import argparse
from pathlib import Path
import sys
import zipfile
from release_version import canonical


def property_value(body, name):
    # Unfold JAR manifest continuation lines. Version values are ASCII in both
    # the generated properties and the manifest.
    lines = body.replace('\r\n', '\n').splitlines()
    values = []
    for line in lines:
        if values and line.startswith(' '):
            values[-1] += line[1:]
        else:
            values.append(line)
    prefix = name + ('=' if name == 'version' else ': ')
    matches = [line[len(prefix):] for line in values if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError(f'Expected exactly one {name} in build metadata')
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag', help='Release tag; with no other arguments prints its normalized version')
    parser.add_argument('built', nargs='?')
    parser.add_argument('--jar', type=Path)
    parser.add_argument('--cli-jar', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    expected = canonical(args.tag)
    if args.built is not None and canonical(args.built) != expected:
        raise ValueError(f'Release tag {args.tag} does not match built version {args.built}; check releaseVersion propagation')
    if args.jar:
        with zipfile.ZipFile(args.jar) as archive:
            for entry, key in [('bypassfuzzer-build.properties', 'version'), ('META-INF/MANIFEST.MF', 'Implementation-Version')]:
                actual = property_value(archive.read(entry).decode('utf-8'), key)
                if actual != expected:
                    raise ValueError(f'{entry} version {actual} does not match {expected}')
    if args.cli_jar:
        with zipfile.ZipFile(args.cli_jar) as archive:
            actual = property_value(archive.read('META-INF/MANIFEST.MF').decode('utf-8'), 'Implementation-Version')
            if actual != expected:
                raise ValueError(f'CLI Implementation-Version {actual} does not match {expected}')
    if args.manifest and args.manifest.read_bytes() != (expected + '\n').encode('utf-8'):
        raise ValueError('Generated version manifest does not match the release version')
    print(expected)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as error:
        sys.exit(str(error))
