#!/usr/bin/env python3
"""Prepare MIT, scan all history, then publish an explicitly selected owned repository."""
import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import public_guard
from tools import binary

HERE = Path(__file__).resolve().parent


def license_files(root):
    return [p for p in root.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING'))]


def is_mit(root):
    return any('Permission is hereby granted, free of charge' in p.read_text(errors='replace')
               and 'The above copyright notice and this permission notice' in p.read_text(errors='replace')
               for p in license_files(root))


def prepare_license(root, holder):
    existing = license_files(root)
    if existing:
        if not is_mit(root):
            raise ValueError('Existing non-MIT license preserved; decide licensing explicitly before publication')
        return False
    text = (HERE / 'LICENSE').read_text()
    text = re.sub(r'Copyright \(c\) \d{4} .+', f'Copyright (c) {date.today().year} {holder}', text, count=1)
    (root / 'LICENSE').write_text(text)
    return True


def command(args, root, capture=True):
    return subprocess.run(args, cwd=root, capture_output=capture, text=True, check=True).stdout


def publish(root, slug, holder, apply=False):
    root = root.resolve()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', slug):
        raise ValueError('Expected OWNER/REPOSITORY')
    if '\n' in holder or not holder.strip():
        raise ValueError('Expected a copyright holder on one line')
    actual = Path(command(['git', 'rev-parse', '--show-toplevel'], root).strip())
    if actual != root:
        raise ValueError('Use the repository root')
    owner = command(['gh', 'api', 'user', '--jq', '.login'], root).strip()
    if slug.split('/')[0].lower() != owner.lower():
        raise ValueError('Publication helper is limited to repositories owned by the authenticated user')
    if command(['git', 'status', '--porcelain'], root).strip():
        raise ValueError('Commit or set aside project changes first; publication needs a clean working tree')
    remote = subprocess.run(['git', 'remote', 'get-url', 'origin'], cwd=root, capture_output=True, text=True)
    if remote.returncode == 0 and public_guard.slug_of(remote.stdout.strip()) != slug:
        raise ValueError('origin does not match the selected GitHub repository')
    metadata = subprocess.run(['gh', 'api', f'repos/{slug}'], cwd=root, capture_output=True, text=True)
    existing = json.loads(metadata.stdout) if metadata.returncode == 0 else None
    if metadata.returncode and '404' not in metadata.stderr:
        raise ValueError('Could not verify GitHub repository state')
    if existing and existing.get('fork'):
        raise ValueError('Upstream fork detected; preserve and review its licensing explicitly')
    branch = command(['git', 'branch', '--show-current'], root).strip()
    if not branch or (existing and branch != existing['default_branch']):
        raise ValueError('Publish from the default branch, not a detached or feature checkout')
    if license_files(root) and not is_mit(root):
        raise ValueError('Existing non-MIT license preserved; resolve the license choice explicitly')
    print(f'Plan: prepare MIT for {holder}, scan all history, push {branch}, make {slug} public')
    if not apply:
        return
    if prepare_license(root, holder):
        command(['git', 'add', '--', 'LICENSE'], root)
        command(['git', 'commit', '-m', 'License project under MIT'], root, capture=False)
    if public_guard.scan_repo(str(root)):
        raise ValueError('Disclosure scan failed; repository visibility was not changed')
    result = subprocess.run([str(binary('gitleaks')), 'git', '--log-opts=--all',
                             '--redact=100', '--no-banner', '--ignore-gitleaks-allow',
                             '--config', str(HERE / 'gitleaks.toml'), str(root)], capture_output=True)
    if result.returncode:
        raise ValueError('Full-history Gitleaks scan failed; inspect locally with redaction before publication')
    if existing is None:
        command(['gh', 'repo', 'create', slug, '--private', '--source', str(root), '--remote', 'origin'], root, capture=False)
    elif remote.returncode:
        command(['git', 'remote', 'add', 'origin', existing['ssh_url']], root)
    command(['git', 'push', '--set-upstream', 'origin', branch], root, capture=False)
    if existing is None or existing['private']:
        command(['gh', 'repo', 'edit', slug, '--visibility', 'public', '--accept-visibility-change-consequences'], root, capture=False)
    observed = json.loads(command(['gh', 'api', f'repos/{slug}'], root))
    if observed['private']:
        raise ValueError('GitHub did not confirm public visibility')
    print('Published: ' + observed['html_url'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repo', type=Path)
    parser.add_argument('--github-repo', required=True)
    parser.add_argument('--copyright-holder', required=True)
    parser.add_argument('--apply', action='store_true', help='Explicit authorization to commit, push and publish this repository')
    args = parser.parse_args()
    try:
        publish(args.repo, args.github_repo, args.copyright_holder, args.apply)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
