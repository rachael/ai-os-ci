#!/usr/bin/env python3
"""Fetch verified official tools explicitly; hooks only use already cached tools."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent


def binary(name, download=False):
    lock = json.loads((HERE / 'tools.lock.json').read_text())[name]
    system = platform.system() + '-' + platform.machine()
    if system not in lock['platforms']:
        raise ValueError(f'No verified {name} binary for {system}; add a reviewed checksum to tools.lock.json')
    asset = lock['platforms'][system]
    cache = Path(os.environ.get('AI_OS_CI_CACHE', Path.home() / '.cache/ai-os/ci'))
    destination = cache / name / lock['version'] / system / name
    receipt = destination.with_suffix('.sha256')
    if destination.is_file() and receipt.is_file():
        if hashlib.sha256(destination.read_bytes()).hexdigest() == receipt.read_text().strip():
            return destination
        raise ValueError(f'Cached {name} changed; remove its cache entry and fetch again')
    if not download:
        raise ValueError(f'{name} is not installed; run the shared AI-OS CI tools.py install')
    url = f'https://github.com/{lock["repository"]}/releases/download/v{lock["version"]}/{asset["asset"]}'
    data = subprocess.check_output(['curl', '--fail', '--silent', '--show-error', '--location',
                                    '--proto', '=https', '--tlsv1.2', '--max-time', '60', url])
    if hashlib.sha256(data).hexdigest() != asset['sha256']:
        raise ValueError(f'{name} release checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.getmember(name)
        if not member.isfile():
            raise ValueError('Expected a regular tool executable')
        payload = archive.extractfile(member).read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temp:
        temp.write(payload)
        temp_path = Path(temp.name)
    temp_path.chmod(0o755)
    os.replace(temp_path, destination)
    receipt.write_text(hashlib.sha256(payload).hexdigest() + '\n')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install'])
    parser.parse_args()
    for name in ['gitleaks', 'actionlint']:
        print(f'{name}: {binary(name, download=True)}')
