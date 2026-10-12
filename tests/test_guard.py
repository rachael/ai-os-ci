import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import public_guard as guard
import install
import run
import publish


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-b', 'main')
        self.git('config', 'core.hooksPath', str(self.root / 'no-hooks'))
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.root / 'README.md').write_text('Fixture project\n')
        self.git('add', '.')
        self.git('commit', '-m', 'Initial fixture')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.addCleanup(patch.stopall)
        patch.object(guard, 'private_terms', return_value=([], '')).start()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True, stderr=subprocess.DEVNULL)

    def test_staged_snapshot_not_worktree_and_no_match_leak(self):
        secret = 'ghp_' + 'aB12' * 10
        path = self.root / 'sample.txt'
        path.write_text(secret)
        self.git('add', 'sample.txt')
        path.write_text('Removed from worktree, but remains staged')
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(guard.scan_changes(self.root, staged=True), 1)
        self.assertNotIn(secret, output.getvalue())
        self.assertIn('credential', output.getvalue())

    def test_sensitive_context_public_only(self):
        (self.root / 'sample.txt').write_text('Fictional diagnosis for a test fixture')
        self.git('add', '.')
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(guard.scan_changes(self.root, staged=True), 1)
            self.assertEqual(guard.scan_changes(self.root, staged=True, credentials_only=True), 0)

    def test_range_and_multiline_commit_message(self):
        self.git('commit', '--allow-empty', '-m', 'Ordinary title', '-m', 'Fictional diagnosis for a test fixture')
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(guard.scan_changes(self.root, self.base), 1)
            self.assertEqual(guard.scan_changes(self.root, self.git('rev-parse', 'HEAD').strip()), 0)

    def test_invalid_ref_cannot_silently_pass(self):
        for ref in ['--all', 'f' * 40, 'HEAD;echo']:
            with self.assertRaises(ValueError):
                guard.scan_changes(self.root, ref)

    def test_missing_explicit_private_terms_fails(self):
        patch.stopall()
        with patch.dict(os.environ, {'PUBLIC_GUARD_TERMS_FILE': str(self.root / 'missing')}):
            with self.assertRaises(ValueError):
                guard.private_terms()

    def test_install_is_idempotent_and_preserves_project_changes(self):
        ref = 'a' * 40
        install.install(self.root, ref, 'private', [{'name': 'sample', 'command': ['python3', '--version']}], True)
        config = self.root / '.ai-os-ci.json'
        data = json.loads(config.read_text())
        data['checks'].append({'name': 'other', 'command': ['git', '--version']})
        config.write_text(json.dumps(data))
        install.install(self.root, 'b' * 40, 'private', [], True)
        self.assertEqual(len(json.loads(config.read_text())['checks']), 2)
        self.assertFalse((self.root / '.ai-os').exists())
        workflow = self.root / '.github/workflows/ai-os.yml'
        workflow.write_text(workflow.read_text() + '# project customization\n')
        with self.assertRaises(ValueError):
            install.install(self.root, ref, 'private', [], True)
        self.assertIn('customization', workflow.read_text())

    def test_real_gitleaks_blocks_staged_credential(self):
        (self.root / '.ai-os-ci.json').write_text(json.dumps({'profile': 'private', 'checks': []}))
        (self.root / 'sample.txt').write_text('token = "' + 'ghp_' + 'aB12' * 10 + '"\n')
        self.git('add', '.')
        with patch.object(run, 'ROOT', self.root), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run.scan(staged=True), 1)

    def test_real_gitleaks_clean_range(self):
        (self.root / '.ai-os-ci.json').write_text(json.dumps({'profile': 'private', 'checks': []}))
        self.git('add', '.')
        self.git('commit', '-m', 'Configure fixture')
        with patch.object(run, 'ROOT', self.root):
            self.assertEqual(run.scan(self.base), 0)

    def test_mit_added_once_with_correct_holder(self):
        self.assertTrue(publish.prepare_license(self.root, 'Example Maintainer'))
        self.assertTrue(publish.is_mit(self.root))
        self.assertIn('Example Maintainer', (self.root / 'LICENSE').read_text())
        before = (self.root / 'LICENSE').read_text()
        self.assertFalse(publish.prepare_license(self.root, 'Another Maintainer'))
        self.assertEqual((self.root / 'LICENSE').read_text(), before)

    def test_existing_non_mit_license_never_replaced(self):
        path = self.root / 'COPYING'
        path.write_text('SPDX-License-Identifier: GPL-3.0-only\n')
        with self.assertRaises(ValueError):
            publish.prepare_license(self.root, 'Example Maintainer')
        self.assertEqual(path.read_text(), 'SPDX-License-Identifier: GPL-3.0-only\n')
        self.assertFalse((self.root / 'LICENSE').exists())


if __name__ == '__main__':
    unittest.main()
