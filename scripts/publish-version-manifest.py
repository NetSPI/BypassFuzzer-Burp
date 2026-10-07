#!/usr/bin/env python3
"""Publish a stable manifest without downgrading the current S3 version.

The caller serializes publication jobs and supplies AWS credentials. Reads must
succeed or report NoSuchKey; access/network errors never permit a blind write.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from release_version import canonical, stable_numbers


def summary(message):
    print(message)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as output:
            output.write(message + '\n')


def publish(manifest, destination, expected):
    candidate = canonical(expected)
    candidate_numbers = stable_numbers(candidate)
    if manifest.read_bytes() != (candidate + '\n').encode('utf-8'):
        raise ValueError('Downloaded manifest does not match the successful build version')
    uri = urlsplit(destination)
    if uri.scheme != 's3' or not uri.netloc or not uri.path.strip('/') or uri.query or uri.fragment:
        raise ValueError('Expected an S3 bucket/key URI')
    with tempfile.TemporaryDirectory(prefix='bypassfuzzer-manifest-') as scratch:
        current = Path(scratch) / 'current.txt'
        read = subprocess.run(['aws', 's3api', 'get-object', '--bucket', uri.netloc,
                               '--key', uri.path.lstrip('/'), str(current)], capture_output=True, text=True)
        if read.returncode:
            if not re.search(r'\(NoSuchKey\)', read.stderr):
                sys.stderr.write(read.stderr)
                raise subprocess.CalledProcessError(read.returncode, read.args)
        else:
            body = current.read_bytes()
            if len(body) > 4096:
                raise ValueError('Invalid existing version manifest')
            text = body.decode('utf-8').strip()
            existing = stable_numbers(text)
            if candidate_numbers <= existing:
                summary(f'S3 version manifest unchanged: current {text} is at least {candidate}.')
                return
        subprocess.run(['aws', 's3', 'cp', str(manifest), destination,
                        '--content-type', 'text/plain', '--cache-control', 'no-cache',
                        '--acl', 'public-read'], check=True)
    summary(f'Published {candidate} to {destination}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('destination')
    parser.add_argument('expected_version')
    args = parser.parse_args()
    try:
        publish(args.manifest, args.destination, args.expected_version)
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
    except (ValueError, OSError) as error:
        sys.exit(str(error))
