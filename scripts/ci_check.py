#!/usr/bin/env python3
"""Run the local, non-networked quality gates for this Skill."""

from __future__ import annotations

import py_compile
import re
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def check_metadata() -> None:
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    if not skill.startswith("---\n") or "\nname: scan-untrusted-code\n" not in skill:
        raise SystemExit("SKILL.md frontmatter is missing or has the wrong name")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_RE.fullmatch(version):
        raise SystemExit(f"Invalid VERSION: {version!r}")
    interface = (ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
    for required in ("display_name:", "short_description:", "default_prompt:"):
        if required not in interface:
            raise SystemExit(f"agents/openai.yaml is missing {required}")


def check_python() -> None:
    python_files = sorted({*ROOT.glob("scripts/*.py"), *ROOT.glob("tests/*.py")})
    with tempfile.TemporaryDirectory(prefix="scan-skill-compile-") as temp:
        output_dir = Path(temp)
        for index, path in enumerate(python_files):
            py_compile.compile(path, cfile=output_dir / f"module-{index}.pyc", doraise=True)


def run_tests() -> None:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]
    print("+", " ".join(command))
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def main() -> int:
    check_metadata()
    check_python()
    run_tests()
    print(f"PASS: {ROOT.name} local CI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
