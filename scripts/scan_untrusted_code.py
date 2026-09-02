#!/usr/bin/env python3
"""Offline, non-executing scanner for untrusted source trees and archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_POINTS = {"info": 0, "low": 3, "medium": 8, "high": 20, "critical": 40}
EXIT_CODES = {"low_indicators": 0, "manual_review": 10, "sandbox_only": 20, "block": 30}

DEFAULT_IGNORED_DIRS = {
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}

TEXT_SUFFIXES = {
    "",
    ".bash",
    ".c",
    ".cfg",
    ".cmd",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".env",
    ".go",
    ".gradle",
    ".h",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".lock",
    ".lua",
    ".m",
    ".md",
    ".php",
    ".plist",
    ".properties",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}

DOC_SUFFIXES = {".md", ".rst", ".adoc"}

AUTOEXEC_BASENAMES = {
    "package.json",
    "setup.py",
    "pyproject.toml",
    "pipfile",
    "makefile",
    "gnumakefile",
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "build.rs",
    "composer.json",
    "gemfile",
    "rakefile",
    "extconf.rb",
    "install.sh",
    "bootstrap.sh",
    "configure",
}

LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    confidence: str
    category: str
    path: str
    line: int | None
    evidence: str
    rationale: str
    source_kind: str = "source_code"
    reachable: bool = False
    base_severity: str = ""


@dataclass
class ScanStats:
    candidates: int = 0
    text_files: int = 0
    binary_files: int = 0
    skipped_large: int = 0
    skipped_limit: int = 0
    unreadable: int = 0
    archives: int = 0


@dataclass
class Candidate:
    path: str
    data: bytes | None
    mode: int | None = None
    link_target: str | None = None
    oversized: bool = False


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    rationale: str
    confidence: str = "Confirmed"


RULES = [
    Rule(
        "REMOTE-FETCH",
        "medium",
        "network",
        re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,320}https?://", re.I),
        "Downloads content from a remote URL.",
    ),
    Rule(
        "REMOTE-PIPE-EXEC",
        "critical",
        "execution",
        re.compile(r"\b(curl|wget)\b[^\n|]{0,500}\|\s*(ba)?sh\b|https?://[^\s]+[^\n]{0,300}\|\s*(node|python\d*)\b", re.I),
        "Pipes remote content directly into an interpreter.",
    ),
    Rule(
        "INTERPRETER-INLINE",
        "high",
        "execution",
        re.compile(r"\bnode\b[^\n]{0,120}\s-\s*$|\bpython\d*\s+-c\b|\b(?:ba)?sh\s+-c\b", re.I),
        "Executes code from stdin or an inline interpreter command.",
    ),
    Rule(
        "SCRIPT-INTERPRETER-EXEC",
        "high",
        "execution",
        re.compile(
            r"\b(node|python\d*|(?:ba)?sh)\b\s+[^|;&\n]{0,260}(?:/tmp/|/var/folders/|\.(?:js|sh|py)\b)",
            re.I,
        ),
        "Executes a script from a source or temporary path.",
    ),
    Rule(
        "DYNAMIC-CODE-EXEC",
        "high",
        "execution",
        re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bchild_process\b|\bexecFileSync\b|\bspawnSync\b", re.I),
        "Uses dynamic evaluation or child-process execution.",
    ),
    Rule(
        "OBFUSCATION-DECODE",
        "high",
        "execution",
        re.compile(r"base64\s+(?:--decode|-d)|Buffer\.from\([^\n]{0,160}base64|atob\s*\(", re.I),
        "Decodes base64 content, which may hide an execution payload.",
    ),
    Rule(
        "TEMP-STAGING",
        "low",
        "staging",
        re.compile(r"\bmktemp\b|/var/folders/|/private/var/folders/|/tmp/|\.upload_", re.I),
        "Creates or references a temporary staging location.",
    ),
    Rule(
        "DESTRUCTIVE-CLEANUP",
        "high",
        "cleanup",
        re.compile(r"\brm\s+(?:-[A-Za-z]*[rf][A-Za-z]*\s+)+|\bunlinkSync\s*\(|\brmSync\s*\(|shutil\.rmtree\s*\(", re.I),
        "Deletes files or directories, potentially to remove evidence.",
    ),
    Rule(
        "BROWSER-CREDENTIAL-PATH",
        "high",
        "sensitive_access",
        re.compile(
            r"(?:[\"'`][^\"'`]{0,80}(?:Login Data(?: For Account)?|Cookies|Web Data|Local Storage|Local Extension Settings)[^\"'`]{0,80}[\"'`]|(?:Google Chrome|Chromium|Microsoft Edge|Brave Browser)[^\n]{0,180}(?:Login Data|Cookies|Web Data|Local Storage|Local Extension Settings))",
            re.I,
        ),
        "References browser credential, cookie, autofill, or extension storage.",
    ),
    Rule(
        "MACOS-KEYCHAIN-ACCESS",
        "high",
        "sensitive_access",
        re.compile(r"login\.keychain-db|security\s+find-(?:generic|internet)-password", re.I),
        "References or queries the macOS login keychain.",
    ),
    Rule(
        "CLIPBOARD-ACCESS",
        "high",
        "sensitive_access",
        re.compile(r"\bpbpaste\b|NSPasteboard|clipboard\.read", re.I),
        "Reads clipboard content that may contain credentials or wallet material.",
    ),
    Rule(
        "SECRET-FILE-DISCOVERY",
        "high",
        "sensitive_access",
        re.compile(r"(?:^|[/~])\.ssh(?:/|\b)|(?:^|[/~])\.aws(?:/|\b)|kubeconfig|\.git-credentials|gh/hosts\.yml|\.netrc|(?:^|[/\s])\.env(?:\*|\b)", re.I),
        "References common credential, cloud, SSH, Git, or environment-secret locations.",
    ),
    Rule(
        "WALLET-EXTENSION",
        "high",
        "sensitive_access",
        re.compile(r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|mcohilncbfahbmgdjkbpemcciiolgcge", re.I),
        "References a known MetaMask, Phantom, or OKX browser extension identifier.",
    ),
    Rule(
        "NETWORK-UPLOAD-CAPABILITY",
        "low",
        "network",
        re.compile(r"socket\.io-client|engine\.io-client|\bform-data\b|\baxios\b|WebSocket\s*\(", re.I),
        "Includes HTTP multipart, Socket.IO, or WebSocket communication capability.",
    ),
    Rule(
        "MACOS-PERSISTENCE",
        "high",
        "persistence",
        re.compile(r"LaunchAgents|LaunchDaemons|launchctl\s+(?:load|bootstrap)|osascript[^\n]{0,160}login item", re.I),
        "References a macOS persistence surface.",
    ),
]


def sanitize_evidence(value: str, limit: int = 240) -> str:
    value = " ".join(value.strip().split())
    value = re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_-]?key|access[_-]?key)(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2[REDACTED]",
        value,
    )
    return value[:limit] + ("..." if len(value) > limit else "")


def classify_path(path: str) -> str:
    """Classify evidence context before applying severity and scoring."""
    normalized = "/" + path.replace("\\", "/").lower().lstrip("/")
    parts = PurePosixPath(normalized).parts
    name = PurePosixPath(normalized).name
    suffix = PurePosixPath(normalized).suffix
    if is_git_hook(path) or is_autoexec(path):
        return "auto_execution"
    if "/.github/workflows/" in normalized:
        return "ci_workflow"
    if "/.github/issue_template/" in normalized or "/.github/pull_request_template" in normalized:
        return "documentation"
    if name in {"readme", "readme.md", "readme.rst", "changelog.md", "contributing.md", "security.md"}:
        return "documentation"
    if suffix in DOC_SUFFIXES:
        return "documentation"
    if any(part in {"test", "tests", "fixtures", "__tests__", "testdata"} for part in parts):
        return "test_fixture"
    if name in {".gitignore", ".dockerignore", ".npmignore", ".gitattributes"}:
        return "metadata"
    if "/.dist-info/" in normalized or name.endswith((".lock", ".lockb")):
        return "dependency_metadata"
    if suffix in {".so", ".dylib", ".dll", ".bin", ".exe"}:
        return "binary"
    return "source_code"


def contextualize_severity(severity: str, path: str, category: str) -> str:
    """Downgrade contextual examples while preserving executable behavior chains."""
    source_kind = classify_path(path)
    if category in {"archive", "behavior_chain"}:
        return severity
    if source_kind in {"documentation", "test_fixture", "metadata"}:
        return {"critical": "medium", "high": "low", "medium": "low", "low": "info"}.get(severity, severity)
    if source_kind == "ci_workflow":
        return {"critical": "high", "high": "medium", "medium": "low"}.get(severity, severity)
    if source_kind == "dependency_metadata":
        return {"critical": "high", "high": "medium"}.get(severity, severity)
    return severity


def add_finding(findings: list[Finding], seen: set[tuple], finding: Finding) -> None:
    source_kind = classify_path(finding.path)
    normalized_finding = replace(
        finding,
        severity=contextualize_severity(finding.severity, finding.path, finding.category),
        source_kind=source_kind,
        reachable=is_autoexec(finding.path) or finding.category == "behavior_chain",
        base_severity=finding.base_severity or finding.severity,
    )
    key = (
        normalized_finding.rule_id,
        normalized_finding.path,
        normalized_finding.line,
        normalized_finding.evidence,
    )
    if key not in seen:
        seen.add(key)
        findings.append(normalized_finding)


def normalized_member_path(name: str) -> str:
    return name.replace("\\", "/")


def unsafe_archive_path(name: str) -> bool:
    normalized = normalized_member_path(name)
    pure = PurePosixPath(normalized)
    return pure.is_absolute() or any(part == ".." for part in pure.parts)


def should_skip_path(relative: str) -> bool:
    parts = PurePosixPath(relative.replace("\\", "/")).parts
    if any(part in DEFAULT_IGNORED_DIRS for part in parts):
        return True
    return len(parts) >= 2 and parts[0] == ".git" and parts[1] == "objects"


def iter_directory(path: Path, max_files: int, max_file_bytes: int, stats: ScanStats) -> Iterator[Candidate]:
    count = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        kept_dirs = []
        for directory in dirs:
            rel = (root_path / directory).relative_to(path).as_posix()
            if not should_skip_path(rel):
                kept_dirs.append(directory)
        dirs[:] = kept_dirs
        for filename in files:
            if count >= max_files:
                stats.skipped_limit += 1
                return
            full = root_path / filename
            rel = full.relative_to(path).as_posix()
            if should_skip_path(rel):
                continue
            count += 1
            try:
                info = full.lstat()
                if stat.S_ISLNK(info.st_mode):
                    yield Candidate(rel, None, info.st_mode, os.readlink(full))
                elif stat.S_ISREG(info.st_mode):
                    if info.st_size > max_file_bytes:
                        yield Candidate(rel, None, info.st_mode, oversized=True)
                    else:
                        yield Candidate(rel, full.read_bytes(), info.st_mode)
            except (OSError, PermissionError):
                stats.unreadable += 1


def iter_single_file(path: Path, max_file_bytes: int, stats: ScanStats) -> Iterator[Candidate]:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            yield Candidate(path.name, None, info.st_mode, os.readlink(path))
        elif info.st_size > max_file_bytes:
            yield Candidate(path.name, None, info.st_mode, oversized=True)
        else:
            yield Candidate(path.name, path.read_bytes(), info.st_mode)
    except (OSError, PermissionError):
        stats.unreadable += 1


def iter_zip(path: Path, max_files: int, max_file_bytes: int, stats: ScanStats) -> Iterator[Candidate]:
    stats.archives += 1
    with zipfile.ZipFile(path) as archive:
        for index, info in enumerate(archive.infolist()):
            if index >= max_files:
                stats.skipped_limit += len(archive.infolist()) - index
                return
            name = normalized_member_path(info.filename)
            if info.is_dir():
                continue
            if unsafe_archive_path(name):
                yield Candidate(name, None, oversized=info.file_size > max_file_bytes)
                continue
            if should_skip_path(name):
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            is_link = stat.S_ISLNK(mode)
            if info.file_size > max_file_bytes:
                yield Candidate(name, None, mode or None, oversized=True)
                continue
            with archive.open(info) as handle:
                data = handle.read(max_file_bytes + 1)
            target = data.decode("utf-8", errors="replace") if is_link else None
            yield Candidate(name, None if is_link else data, mode or None, target)


def iter_tar(path: Path, max_files: int, max_file_bytes: int, stats: ScanStats) -> Iterator[Candidate]:
    stats.archives += 1
    with tarfile.open(path, mode="r:*") as archive:
        for index, info in enumerate(archive):
            if index >= max_files:
                stats.skipped_limit += 1
                return
            name = normalized_member_path(info.name)
            if info.isdir():
                continue
            if unsafe_archive_path(name):
                yield Candidate(name, None, oversized=info.size > max_file_bytes)
                continue
            if should_skip_path(name):
                continue
            if info.issym() or info.islnk():
                yield Candidate(name, None, info.mode, info.linkname)
            elif info.isfile():
                if info.size > max_file_bytes:
                    yield Candidate(name, None, info.mode, oversized=True)
                    continue
                handle = archive.extractfile(info)
                if handle is not None:
                    with handle:
                        yield Candidate(name, handle.read(max_file_bytes + 1), info.mode)


def candidate_iterator(path: Path, max_files: int, max_file_bytes: int, stats: ScanStats) -> Iterable[Candidate]:
    if path.is_dir():
        return iter_directory(path, max_files, max_file_bytes, stats)
    if zipfile.is_zipfile(path):
        return iter_zip(path, max_files, max_file_bytes, stats)
    if tarfile.is_tarfile(path):
        return iter_tar(path, max_files, max_file_bytes, stats)
    return iter_single_file(path, max_file_bytes, stats)


def is_git_hook(path: str) -> bool:
    normalized = "/" + path.replace("\\", "/").lower().lstrip("/")
    if "/.git/hooks/" not in normalized:
        return False
    name = normalized.rsplit("/", 1)[-1]
    return not name.endswith(".sample") and name not in {"", ".gitkeep"}


def is_autoexec(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = PurePosixPath(normalized).name
    return (
        is_git_hook(path)
        or name in AUTOEXEC_BASENAMES
        or normalized.endswith("/.vscode/tasks.json")
        or normalized.endswith("/.vscode/settings.json")
        or "/.devcontainer/" in "/" + normalized
        or normalized.endswith("/.git/config")
        or normalized.endswith("/.gitattributes")
    )


def load_ioc_packs(paths: list[Path]) -> list[dict]:
    indicators: list[dict] = []
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        for indicator in payload.get("indicators", []):
            required = {"rule_id", "type", "value", "severity", "rationale"}
            if not required.issubset(indicator):
                raise ValueError(f"Malformed IOC in {path}: {indicator}")
            if indicator["severity"] not in SEVERITY_RANK:
                raise ValueError(f"Invalid IOC severity in {path}: {indicator['severity']}")
            indicators.append(indicator)
    return indicators


def add_path_findings(candidate: Candidate, findings: list[Finding], seen: set[tuple]) -> None:
    path = candidate.path
    normalized = "/" + path.replace("\\", "/").lower().lstrip("/")
    if unsafe_archive_path(path):
        add_finding(
            findings,
            seen,
            Finding(
                "ARCHIVE-PATH-TRAVERSAL",
                "critical",
                "Confirmed",
                "archive",
                path,
                None,
                sanitize_evidence(path),
                "Archive entry escapes the intended extraction root or uses an absolute path.",
            ),
        )
    if candidate.link_target is not None:
        severity = "high" if unsafe_archive_path(candidate.link_target) or os.path.isabs(candidate.link_target) else "medium"
        add_finding(
            findings,
            seen,
            Finding(
                "SYMLINK-OR-HARDLINK",
                severity,
                "Confirmed",
                "archive",
                path,
                None,
                sanitize_evidence(f"link -> {candidate.link_target}"),
                "Link may redirect access outside the reviewed source tree.",
            ),
        )
    if is_git_hook(path):
        executable = bool(candidate.mode and candidate.mode & 0o111)
        add_finding(
            findings,
            seen,
            Finding(
                "GIT-HOOK-PRESENT",
                "high",
                "Confirmed",
                "auto_execution",
                path,
                None,
                "non-sample Git hook" + ("; executable" if executable else ""),
                "A repository-local Git hook can execute during normal Git operations.",
            ),
        )
    if normalized.endswith("/.git/config"):
        add_finding(
            findings,
            seen,
            Finding(
                "DISTRIBUTED-GIT-CONFIG",
                "medium",
                "Confirmed",
                "auto_execution",
                path,
                None,
                ".git/config is present",
                "A downloaded full Git directory can contain local execution settings not delivered by a normal clone.",
            ),
        )
    if any(token in normalized for token in ("/launchagents/", "/launchdaemons/")) and normalized.endswith(".plist"):
        add_finding(
            findings,
            seen,
            Finding(
                "MACOS-PERSISTENCE-FILE",
                "high",
                "Confirmed",
                "persistence",
                path,
                None,
                "LaunchAgent/LaunchDaemon plist",
                "A launchd plist may establish persistence if installed.",
            ),
        )


def add_package_findings(path: str, text: str, findings: list[Finding], seen: set[tuple]) -> None:
    if PurePosixPath(path.lower()).name != "package.json":
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    scripts = payload.get("scripts", {})
    if not isinstance(scripts, dict):
        return
    for name, command in scripts.items():
        if name in LIFECYCLE_SCRIPTS and isinstance(command, str) and command.strip():
            suspicious = bool(
                re.search(
                    r"https?://|\b(curl|wget|powershell|bash|sh|node|python)\b|\b(eval|base64|child_process)\b|(?:Login Data|Cookies|\.ssh|\.aws|kubeconfig)",
                    command,
                    re.I,
                )
            )
            add_finding(
                findings,
                seen,
                Finding(
                    "NPM-LIFECYCLE-SCRIPT",
                    "high" if suspicious else "medium",
                    "Confirmed",
                    "auto_execution",
                    path,
                    None,
                    sanitize_evidence(f"{name}: {command}"),
                    "npm may execute this lifecycle script during install or packaging; review the command before installation."
                    if suspicious
                    else "npm may execute this lifecycle script during install or packaging; this appears to be a normal build command but still needs review.",
                ),
            )


def add_content_findings(
    candidate: Candidate,
    text: str,
    indicators: list[dict],
    findings: list[Finding],
    seen: set[tuple],
) -> None:
    path = candidate.path
    hit_counts: Counter[tuple[str, str]] = Counter()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if rule.rule_id == "SECRET-FILE-DISCOVERY" and PurePosixPath(path.lower()).name in {".gitignore", ".dockerignore", ".npmignore"}:
                continue
            if hit_counts[(path, rule.rule_id)] >= 3:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            add_finding(
                findings,
                seen,
                Finding(
                    rule.rule_id,
                    rule.severity,
                    rule.confidence,
                    rule.category,
                    path,
                    line_number,
                    sanitize_evidence(line),
                    rule.rationale,
                ),
            )
            hit_counts[(path, rule.rule_id)] += 1

    lower_path = path.lower()
    lower_text = text.lower()
    for indicator in indicators:
        value = str(indicator["value"])
        lower_value = value.lower()
        indicator_type = indicator["type"]
        path_hit = lower_value in lower_path
        content_hit = lower_value in lower_text
        if indicator_type == "path" and not path_hit:
            continue
        if indicator_type == "content" and not content_hit:
            continue
        if indicator_type == "path_or_content" and not (path_hit or content_hit):
            continue
        if indicator_type not in {"path", "content", "path_or_content"}:
            continue
        line_number = None
        evidence = f"IOC matched in path: {value}" if path_hit else f"IOC matched in content: {value}"
        if content_hit:
            for index, line in enumerate(text.splitlines(), start=1):
                if lower_value in line.lower():
                    line_number = index
                    evidence = sanitize_evidence(line)
                    break
        add_finding(
            findings,
            seen,
            Finding(
                indicator["rule_id"],
                indicator["severity"],
                "Confirmed",
                "ioc",
                path,
                line_number,
                evidence,
                indicator["rationale"],
            ),
        )


def add_combination_findings(findings: list[Finding], seen: set[tuple]) -> None:
    by_path: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_path[finding.path].append(finding)
    for path, path_findings in by_path.items():
        ids = {finding.rule_id for finding in path_findings}
        categories = {finding.category for finding in path_findings}
        if "GIT-HOOK-PRESENT" in ids and "REMOTE-FETCH" in ids and categories & {"execution"}:
            add_finding(
                findings,
                seen,
                Finding(
                    "COMBO-GIT-HOOK-REMOTE-EXEC",
                    "critical",
                    "High Confidence",
                    "behavior_chain",
                    path,
                    None,
                    "Git hook + remote fetch + interpreter execution",
                    "A Git operation can trigger download and execution of remote code.",
                ),
            )
        if "sensitive_access" in categories and "network" in categories:
            add_finding(
                findings,
                seen,
                Finding(
                    "COMBO-SENSITIVE-DATA-NETWORK",
                    "critical",
                    "High Confidence",
                    "behavior_chain",
                    path,
                    None,
                    "sensitive-data access + network/upload capability",
                    "The same file contains both sensitive-data collection and network capability.",
                ),
            )
        if {"staging", "cleanup", "network"}.issubset(categories):
            add_finding(
                findings,
                seen,
                Finding(
                    "COMBO-STAGE-NETWORK-CLEANUP",
                    "high",
                    "High Confidence",
                    "behavior_chain",
                    path,
                    None,
                    "temporary staging + network capability + cleanup",
                    "The behavior chain is consistent with collecting, transferring, and deleting staged data.",
                ),
            )


def score_findings(findings: list[Finding]) -> tuple[int, list[dict]]:
    """Score unique rule/path pairs so repeated examples cannot inflate the verdict."""
    by_key: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.path)
        current = by_key.get(key)
        if current is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current.severity]:
            by_key[key] = finding
    breakdown = []
    for finding in sorted(by_key.values(), key=lambda item: (-SEVERITY_RANK[item.severity], item.path, item.rule_id)):
        breakdown.append(
            {
                "rule_id": finding.rule_id,
                "path": finding.path,
                "severity": finding.severity,
                "source_kind": finding.source_kind,
                "points": SEVERITY_POINTS[finding.severity],
            }
        )
    return min(100, sum(item["points"] for item in breakdown)), breakdown


def is_block_signal(finding: Finding) -> bool:
    """Require a critical, actionable signal instead of score accumulation alone."""
    if finding.severity != "critical":
        return False
    if finding.category in {"archive", "behavior_chain"}:
        return True
    if finding.category == "ioc" and finding.source_kind in {"source_code", "auto_execution"}:
        return True
    if finding.rule_id == "REMOTE-PIPE-EXEC" and finding.source_kind in {"source_code", "auto_execution"}:
        return True
    return finding.source_kind not in {"documentation", "test_fixture", "metadata", "ci_workflow"}


def scan(path: Path, max_files: int, max_file_bytes: int, indicators: list[dict]) -> dict:
    findings: list[Finding] = []
    seen: set[tuple] = set()
    stats = ScanStats()
    for candidate in candidate_iterator(path, max_files, max_file_bytes, stats):
        stats.candidates += 1
        add_path_findings(candidate, findings, seen)
        if candidate.oversized:
            stats.skipped_large += 1
            continue
        if candidate.data is None:
            continue
        if len(candidate.data) > max_file_bytes:
            stats.skipped_large += 1
            continue
        sample = candidate.data[:8192]
        if b"\x00" in sample:
            stats.binary_files += 1
            continue
        suffix = PurePosixPath(candidate.path.lower()).suffix
        if suffix not in TEXT_SUFFIXES and not is_autoexec(candidate.path):
            stats.binary_files += 1
            continue
        text = candidate.data.decode("utf-8", errors="replace")
        stats.text_files += 1
        add_package_findings(candidate.path, text, findings, seen)
        add_content_findings(candidate, text, indicators, findings, seen)
    add_combination_findings(findings, seen)
    findings.sort(
        key=lambda item: (
            -SEVERITY_RANK[item.severity],
            item.path,
            item.line or 0,
            item.rule_id,
        )
    )
    score, score_breakdown = score_findings(findings)
    highest = max((SEVERITY_RANK[finding.severity] for finding in findings), default=0)
    block_signals = [finding for finding in findings if is_block_signal(finding)]
    if block_signals:
        verdict = "block"
        verdict_basis = "actionable critical indicator or confirmed high-confidence behavior chain"
    elif highest >= SEVERITY_RANK["high"] or score >= 40:
        verdict = "sandbox_only"
        verdict_basis = "high-severity capability requires isolated review before execution"
    elif highest >= SEVERITY_RANK["medium"] or score >= 15:
        verdict = "manual_review"
        verdict_basis = "contextual or medium-severity indicators require human review"
    else:
        verdict = "low_indicators"
        verdict_basis = "no configured high-risk indicator found"
    artifact_hash = None
    if path.is_file():
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        artifact_hash = digest.hexdigest()
    return {
        "scanner": {"name": "scan-untrusted-code", "version": "1.1.1"},
        "target": {"path": str(path.resolve()), "sha256": artifact_hash},
        "verdict": verdict,
        "risk_score": score,
        "verdict_basis": verdict_basis,
        "block_signals": [
            {
                "rule_id": finding.rule_id,
                "path": finding.path,
                "severity": finding.severity,
                "confidence": finding.confidence,
            }
            for finding in block_signals
        ],
        "score_breakdown": score_breakdown,
        "context_summary": dict(Counter(finding.source_kind for finding in findings)),
        "highest_severity": next((name for name, rank in SEVERITY_RANK.items() if rank == highest), "info"),
        "summary": dict(Counter(finding.severity for finding in findings)),
        "stats": asdict(stats),
        "findings": [asdict(finding) for finding in findings],
        "limitations": [
            "Static inspection cannot prove that an artifact is safe.",
            "Runtime-fetched, encrypted, obfuscated, oversized, or generated payloads may not be visible.",
            "A network/upload capability does not prove successful data transfer.",
            "Repository reputation and dependency vulnerability lookups are outside the offline V1.1 scan.",
            "Binary metadata, code-signing, and package provenance checks are reserved for a later macOS/Python extension.",
        ],
    }


def markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    lines = [
        "# Untrusted Code Static Scan",
        "",
        f"- Target: `{report['target']['path']}`",
        f"- Verdict: **{report['verdict']}**",
        f"- Risk score: **{report['risk_score']}/100**",
        f"- Highest severity: **{report['highest_severity']}**",
        f"- Verdict basis: {report['verdict_basis']}",
    ]
    if report["target"]["sha256"]:
        lines.append(f"- Artifact SHA256: `{report['target']['sha256']}`")
    lines.extend(
        [
            "",
            "A low finding count means only that configured rules found no high-risk indicator. It is not a safety guarantee.",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|---|---:|",
        ]
    )
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity} | {report['summary'].get(severity, 0)} |")
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Severity | Confidence | Context | Reachable | Rule | Path | Line | Evidence | Rationale |",
            "|---|---|---|---|---|---|---:|---|---|",
        ]
    )
    if not report["findings"]:
        lines.append("| info | Not Confirmed | - | - | NONE | - | - | No configured indicator found | Continue normal controls |")
    for finding in report["findings"]:
        lines.append(
            "| {severity} | {confidence} | {source_kind} | {reachable} | {rule_id} | `{path}` | {line} | {evidence} | {rationale} |".format(
                severity=markdown_escape(finding["severity"]),
                confidence=markdown_escape(finding["confidence"]),
                source_kind=markdown_escape(finding["source_kind"]),
                reachable="yes" if finding["reachable"] else "no",
                rule_id=markdown_escape(finding["rule_id"]),
                path=markdown_escape(finding["path"]),
                line=finding["line"] or "-",
                evidence=markdown_escape(finding["evidence"]),
                rationale=markdown_escape(finding["rationale"]),
            )
        )
    lines.extend(
        [
            "",
            "## Context summary",
            "",
            "```json",
            json.dumps(report["context_summary"], indent=2),
            "```",
            "",
            "## Score breakdown",
            "",
            "```json",
            json.dumps(report["score_breakdown"], indent=2),
            "```",
            "",
            "## Scan statistics",
            "",
            "```json",
            json.dumps(report["stats"], indent=2),
            "```",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="Local directory, file, ZIP, or TAR artifact")
    parser.add_argument("--format", choices=("markdown", "json", "both"), default="markdown")
    parser.add_argument("--output-dir", type=Path, help="Write scan-report.md/json into this directory")
    parser.add_argument("--ioc-pack", action="append", type=Path, default=[], help="Additional IOC pack JSON; repeatable")
    parser.add_argument("--no-default-ioc-pack", action="store_true", help="Disable the bundled daam IOC pack")
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--exit-zero", action="store_true", help="Always return exit code 0 without changing verdict")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.target.exists() and not args.target.is_symlink():
        parser.error(f"Target does not exist: {args.target}")
    if args.max_files <= 0 or args.max_file_bytes <= 0:
        parser.error("Scan limits must be positive")
    if args.format == "both" and args.output_dir is None:
        parser.error("--format both requires --output-dir")
    skill_root = Path(__file__).resolve().parent.parent
    ioc_paths = list(args.ioc_pack)
    if not args.no_default_ioc_pack:
        ioc_paths.insert(0, skill_root / "references" / "ioc-pack-daam-node-stealer.json")
    try:
        indicators = load_ioc_packs(ioc_paths)
        report = scan(args.target, args.max_files, args.max_file_bytes, indicators)
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"scan error: {exc}", file=sys.stderr)
        return 2
    markdown = render_markdown(report)
    json_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        if args.format in {"markdown", "both"}:
            (args.output_dir / "scan-report.md").write_text(markdown, encoding="utf-8")
        if args.format in {"json", "both"}:
            (args.output_dir / "scan-report.json").write_text(json_text, encoding="utf-8")
    elif args.format == "markdown":
        print(markdown)
    elif args.format == "json":
        print(json_text, end="")
    return 0 if args.exit_zero else EXIT_CODES[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
