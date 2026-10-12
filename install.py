#!/usr/bin/env python3
"""Enroll a repository with tiny workflow callers and its own test configuration."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def workflows(ref):
    if not re.fullmatch('[0-9a-f]{40}', ref):
        raise ValueError('Use a full ai-os-ci commit SHA')
    return {
        '.github/workflows/ai-os.yml': '''# Managed by ai-os-ci/install.py; project tests live in .ai-os-ci.json.
name: AI-OS checks
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: ai-os-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
jobs:
  checks:
    uses: rachael/ai-os-ci/.github/workflows/checks.yml@''' + ref + '''
    with:
      tooling-ref: ''' + ref + '\n',
        '.github/workflows/ai-os-review.yml': '''# Managed by ai-os-ci/install.py; metadata only, no pull-request checkout.
name: Request review
on:
  pull_request_target:
    types: [opened, ready_for_review, reopened]
permissions:
  pull-requests: write
jobs:
  request:
    uses: rachael/ai-os-ci/.github/workflows/review.yml@''' + ref + '\n',
    }


def install(root, ref, profile, checks, apply=False):
    root = root.resolve()
    actual = Path(subprocess.check_output(['git', '-C', str(root), 'rev-parse', '--show-toplevel'], text=True).strip())
    if root != actual:
        raise ValueError('Use the repository root')
    path = root / '.ai-os-ci.json'
    current = json.loads(path.read_text()) if path.exists() else None
    config = current or {'schemaVersion': 1, 'profile': profile, 'checks': checks}
    if config['profile'] != profile:
        raise ValueError('Disclosure profile differs; review and edit .ai-os-ci.json explicitly')
    old = workflows(config['toolingRef']) if config.get('toolingRef') else {}
    files = workflows(ref)
    for rel, content in files.items():
        destination = root / rel
        for parent in [destination, *destination.parents]:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError(f'Refusing symlink destination: {rel}')
        if destination.exists() and destination.read_text() not in (content, old.get(rel)):
            raise ValueError(f'Existing workflow has local changes: {rel}')
    if path.is_symlink():
        raise ValueError('Refusing symlink configuration')
    config['toolingRef'] = ref
    files['.ai-os-ci.json'] = json.dumps(config, indent=2) + '\n'
    if apply:
        for rel, content in files.items():
            destination = root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content)
    print(('Installed' if apply else 'Prepared') + ' shared CI callers; no guard/tool copies in the project')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', type=Path)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--profile', choices=['public', 'private'], required=True)
    parser.add_argument('--check', action='append', default=[], metavar='NAME=COMMAND')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    checks = []
    for item in args.check:
        name, sep, command = item.partition('=')
        if not sep or not name or not command:
            parser.error('--check expects NAME=COMMAND')
        checks.append({'name': name, 'command': shlex.split(command)})
    try:
        install(args.repo, args.ref, args.profile, checks, args.apply)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
