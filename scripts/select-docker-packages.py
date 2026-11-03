#!/usr/bin/env python3
"""Select exact Docker package versions and validated paths from Packages.gz."""
import gzip
import re
import sys


def select_packages(metadata, arch, suite, pins):
    if arch not in ('amd64', 'arm64') or not re.fullmatch('[a-z]+', suite):
        raise ValueError('Invalid Docker distribution/architecture.')
    found = {}
    with gzip.open(metadata, 'rt') as stream:
        blocks = stream.read().split('\n\n')
    for block in blocks:
        fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
        name = fields.get('Package')
        if name not in pins or fields.get('Architecture') != arch:
            continue
        version = fields.get('Version', '').split(':')[-1]
        if not re.match(re.escape(pins[name]) + r'(?=[-~+]|$)', version):
            continue
        path, sha = fields.get('Filename', ''), fields.get('SHA256', '')
        if not re.fullmatch(r'dists/' + suite + r'/pool/stable/' + arch + r'/[A-Za-z0-9_.+%~:-]+\.deb', path) or not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('Invalid filename/checksum in Docker metadata.')
        if not path.rsplit('/', 1)[-1].startswith(name + '_'):
            raise ValueError('Unexpected package filename in Docker metadata.')
        found[name] = (path, sha)
    if set(found) != set(pins):
        raise ValueError('Pinned Docker packages unavailable in mirror metadata; no alternate version installed.')
    return [found[name] for name in pins]


if __name__ == '__main__':
    for row in select_packages(sys.argv[1], sys.argv[2], sys.argv[3], dict(item.split('=', 1) for item in sys.argv[4:])):
        print(*row)
