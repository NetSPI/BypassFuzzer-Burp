"""Release version parsing shared by CI validation and stable publication."""
import re

_VERSION = re.compile(
    r'[vV]?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?'
    r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
    r'(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?')


def canonical(value):
    match = _VERSION.fullmatch(value) if len(value) <= 128 else None
    if not match:
        raise ValueError('Invalid release version')
    major, minor, patch, pre, metadata = match.groups()
    if pre and any(re.fullmatch(r'0[0-9]+', part) for part in pre.split('.')):
        raise ValueError('Invalid numeric prerelease identifier')
    return f'{major}.{minor}.{patch or "0"}' + (f'-{pre}' if pre else '') + (f'+{metadata}' if metadata else '')


def stable_numbers(value):
    version = canonical(value)
    if '-' in version.split('+', 1)[0]:
        raise ValueError('The stable manifest must contain a stable release version')
    return tuple(map(int, version.split('+', 1)[0].split('.')))
