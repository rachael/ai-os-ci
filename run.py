#!/usr/bin/env python3
"""The same deterministic checks in Git hooks and GitHub Actions; no model calls."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from tools import binary

HERE = Path(__file__).resolve().parent
ROOT = Path.cwd()
PROFILE = None


def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, capture_output=True, check=True).stdout


def config():
    result = json.loads((ROOT / '.ai-os-ci.json').read_text())
    if PROFILE:
        result['profile'] = PROFILE
    return result


def scan(base=None, head='HEAD', staged=False):
    settings = config()
    if settings['profile'] not in ('private', 'public'):
        raise ValueError('Unknown disclosure profile')
    for ref in ([] if staged else [head] + ([base] if base else [])):
        if ref != 'HEAD' and not re.fullmatch(r'[0-9a-fA-F]{40,64}', ref):
            raise ValueError('Scan refs must be full commit IDs or HEAD')
        git('cat-file', '-e', ref + '^{commit}')
    guard = HERE / 'public_guard.py'
    spec = importlib.util.spec_from_file_location('public_guard', guard)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    code = module.scan_changes(str(ROOT), base, head, staged, settings['profile'] == 'private')
    # Do not let reports echo secrets, source lines, or identities into CI logs.
    command = [str(binary('gitleaks')), '--redact=100', '--no-banner', '--exit-code=23', '--ignore-gitleaks-allow']
    if staged:
        command += ['git', '--pre-commit', '--staged', str(ROOT)]
    else:
        revs = f'{base}..{head}' if base else head
        command += ['git', '--log-opts=' + revs, str(ROOT)]
    # Use built-in detector policy, not a PR-supplied GITLEAKS_CONFIG.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GITLEAKS_')}
    env['GITLEAKS_CONFIG'] = str(HERE / 'gitleaks.toml')
    result = subprocess.run(command, cwd=ROOT, capture_output=True, env=env)
    if result.returncode not in (0, 23):
        raise ValueError(f'Gitleaks could not complete (exit {result.returncode}); no clean result produced')
    print('Gitleaks: ' + ('findings detected; run locally with --redact=100 to inspect' if result.returncode else 'clean'))
    return max(code, int(result.returncode != 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    global ROOT, PROFILE
    parser.add_argument('action', choices=['check', 'staged', 'pre-push'])
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--profile', choices=['private', 'public'])
    parser.add_argument('hook_args', nargs='*')
    parser.add_argument('--base')
    parser.add_argument('--head', default='HEAD')
    args = parser.parse_args()
    ROOT = args.repo.resolve()
    PROFILE = args.profile
    if args.action == 'staged':
        # An unborn repository has no HEAD, but staged content is still scannable.
        return scan(staged=True)
    if args.action == 'pre-push':
        code = 0
        for line in sys.stdin.read().splitlines():
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) != 4:
                raise ValueError('Malformed pre-push input')
            head, base = fields[1], fields[3]
            if set(head) == {'0'}:
                continue
            code = max(code, scan(None if set(base) == {'0'} else base, head))
        return code
    base = args.base or None
    if base and set(base) == {'0'}:
        base = None
    code = scan(base, args.head)
    workflows = sorted((ROOT / '.github/workflows').glob('*.y*ml'))
    if workflows:
        code = max(code, subprocess.run([str(binary('actionlint')), '-shellcheck=', *map(str, workflows)], cwd=ROOT).returncode)
    for check in config().get('checks', []):
        print('Check: ' + check['name'], flush=True)
        code = max(code, subprocess.run(check['command'], cwd=ROOT).returncode)
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f'AI-OS CI could not complete: {exc}', file=sys.stderr)
        sys.exit(2)
