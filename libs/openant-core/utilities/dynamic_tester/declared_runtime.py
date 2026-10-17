"""#521 finding 1: the declared-runtime channel (the mechanical input).

The #519 policy tells the model to prefer the scanned target's DECLARED
runtime (go.mod / .python-version / requires-python / engines) — but no
code ever read those manifests into the prompt: the declared branch was
dead input, reachable only via a version cue that happens to sit in the
finding text. This module derives the declarations from the repo root
and the prompt interpolates one allowlist-fenced line per language.

Security posture (the prompt's output is EXECUTED — docker build/run):
manifest content is repo-author-controlled. Every derived value must
match a strict version grammar; anything else is OMITTED entirely (never
interpolated, never raised — a raise at the derivation site would abort
the whole dynamic-test step before any finding is tested). This is
strictly TIGHTER than the existing inline surface (nine collapsed free-
text lines): the derived lines carry zero free-text capacity.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Optional

# The version grammar — the ONLY thing that can ride the prompt line.
# A version string has no business carrying free text.
_VERSION_RE = re.compile(r"[0-9]+(\.[0-9]+){0,2}(-[A-Za-z0-9.]+)?")
_NUMERIC_VERSION = r"[0-9]+(?:\.[0-9]+){0,2}"
_MAX_MANIFEST_BYTES = 65_536  # bounded read: a manifest is KB-scale, not MB


def _clean_version(raw: object) -> Optional[str]:
    """A value that matches the version grammar, or None (omit)."""
    if not isinstance(raw, str):
        return None
    v = raw.strip()
    if not v or len(v) > 32 or not _VERSION_RE.fullmatch(v):
        return None
    return v


def _read_bounded(path: Path) -> Optional[str]:
    # The fable gate: a manifest under a scanned repo is attacker-controlled
    # — a SYMLINK to /dev/zero reads unbounded (st_size 0, infinite stream)
    # and a FIFO/device wedges the step. Use the repo's own read_repo_file
    # (lstat-before-open, symlink/device refusal, bounded read — the same
    # guard every other repo-file loader uses), degraded to absent on refusal.
    from utilities.file_io import read_repo_file
    try:
        return read_repo_file(path, max_bytes=_MAX_MANIFEST_BYTES)
    except Exception:
        # read_repo_file raises UnsafeRepoFile (symlink/device/oversize — the
        # #258 guard classes); the declared channel degrades to ABSENT, never
        # raises (a raise here would abort the dynamic-test step).
        return None


def _from_go_mod(text: str) -> Optional[str]:
    # `go` is the minimum version; `toolchain` can recommend a newer one.
    # Only stable numeric toolchains are accepted, never an arbitrary binary
    # name or suffix. Comments are data and cannot enter the version channel.
    versions: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("//", 1)[0].strip()
        match = re.fullmatch(rf"(go|toolchain)\s+(go)?({_NUMERIC_VERSION})", line)
        if not match or bool(match[2]) != (match[1] == "toolchain"):
            continue
        version = _clean_version(match[3])
        if version:
            versions[match[1]] = version
    # A stale toolchain suggestion must not lower the module's minimum.
    return max((versions[key] for key in ("toolchain", "go") if key in versions),
               key=_version_tuple, default=None)


def _version_tuple(version: str) -> tuple[int, int, int]:
    parts = [int(part) for part in version.split(".")]
    return tuple((parts + [0, 0])[:3])


def _family_end(version: str) -> Optional[tuple[int, int, int]]:
    parts = [int(part) for part in version.split(".")]
    if len(parts) == 3:
        return None  # a full patch version is already exact
    parts[-1] += 1
    return tuple((parts + [0, 0])[:3])


def _pin_under_ceiling(lower: str, upper: tuple[int, int, int]) -> Optional[str]:
    # A family tag (3.11 / 20) may resolve ABOVE a ceiling inside that family.
    # Pin its initial release in that case, preserving the allowed lower bound.
    family_end = _family_end(lower)
    if family_end is not None and upper < family_end:
        return _clean_version(".".join(map(str, _version_tuple(lower))))
    return lower


def _from_pyproject(text: str) -> Optional[str]:
    # Conservative stable-version subset of requires-python. Parse the WHOLE
    # expression; extracting a numeric prefix from >=3.11evil invents a floor.
    try:
        req = tomllib.loads(text).get("project", {}).get("requires-python", "")
    except (tomllib.TOMLDecodeError, AttributeError, RecursionError, ValueError):
        return None
    if not isinstance(req, str) or len(req) > 256:
        return None
    req = req.strip()
    exact = re.fullmatch(rf"==\s*({_NUMERIC_VERSION})(\.\*)?", req)
    if exact:
        version = _clean_version(exact[1])
        if version and not exact[2]:
            # PEP 440 ==3.11 is exactly 3.11.0; the Docker family tag 3.11
            # could select a later patch. ==3.11.* intentionally keeps it.
            version = _clean_version(".".join(map(str, _version_tuple(version))))
        return version
    compatible = re.fullmatch(r"~=\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", req)
    if compatible:
        return _clean_version(compatible[1])

    constraints: list[tuple[str, str]] = []
    for clause in req.split(","):
        match = re.fullmatch(rf"(>=|<=|<)\s*({_NUMERIC_VERSION})", clause.strip())
        if not match:
            # Exclusions, prereleases and exclusive lower bounds need full
            # PEP 440 solving. Omit them instead of selecting an invalid floor.
            return None
        version = _clean_version(match[2])
        if not version:
            return None
        constraints.append((match[1], version))
    lower = max((v for op, v in constraints if op == ">="),
                key=_version_tuple, default=None)
    if lower is None:
        return None  # an upper bound alone is not a declared runtime
    for op, version in constraints:
        if op == ">=":
            continue
        if (_version_tuple(lower) > _version_tuple(version)
                or (op == "<" and _version_tuple(lower) == _version_tuple(version))):
            return None
        lower = _pin_under_ceiling(lower, _version_tuple(version))
        if lower is None:
            return None
    return lower


def _from_python_version(text: str) -> Optional[str]:
    # .python-version: one bare version per line
    for line in text.splitlines():
        v = line.strip()
        if v and not v.startswith("#"):
            return _clean_version(v)
    return None


def _from_package_json(text: str) -> Optional[str]:
    # A conservative subset of npm engine syntax. An unanchored >= search
    # silently lost exact pins and accepted malformed ranges/instruction text.
    try:
        engines = json.loads(text).get("engines", {})
    except (json.JSONDecodeError, AttributeError, RecursionError, ValueError):
        # RecursionError: deeply-nested hostile json (64KB of "[[[[") blows
        # the stdlib's parser stack — degrade to absent, never abort the step.
        return None
    node = engines.get("node") if isinstance(engines, dict) else None
    if not isinstance(node, str) or len(node) > 128:
        return None
    node = node.strip()
    exact = re.fullmatch(rf"(?:[v=^~]\s*)?({_NUMERIC_VERSION})", node)
    if exact:
        return _clean_version(exact[1])
    wildcard = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\.[xX*]", node)
    if wildcard is None:
        wildcard = re.fullmatch(r"([0-9]+)\.[xX*]\.[xX*]", node)
    if wildcard:
        return _clean_version(wildcard[1])
    bounded = re.fullmatch(
        rf">=\s*({_NUMERIC_VERSION})(?:\s+(<=?)\s*({_NUMERIC_VERSION}))?", node)
    if not bounded:
        # OR ranges, exclusive lower bounds and upper-bound-only constraints
        # cannot be reduced to one safe declaration by this small parser.
        return None
    lower = _clean_version(bounded[1])
    upper = _clean_version(bounded[3]) if bounded[3] else None
    if not lower or (bounded[3] and not upper):
        return None
    if upper:
        upper_tuple, operator = _version_tuple(upper), bounded[2]
        # npm <=22 and <=22.1 include the whole named family; unlike PEP 440,
        # they do not mean <=22.0.0 / <=22.1.0.
        family_end = _family_end(upper)
        if operator == "<=" and family_end is not None:
            upper_tuple, operator = family_end, "<"
        if (_version_tuple(lower) > upper_tuple
                or (operator == "<" and _version_tuple(lower) == upper_tuple)):
            return None
        return _pin_under_ceiling(lower, upper_tuple)
    return lower


def _from_tool_versions(text: str) -> dict[str, str]:
    # .tool-versions: '<tool> <version>' per line (golang 1.24 / python 3.12)
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) == 2:
            tool, ver = parts[0].lower(), _clean_version(parts[1])
            if ver:
                out[tool] = ver
    return out


def derive_declared_runtimes(repo_path: Optional[str]) -> dict[str, str]:
    """Declared runtime versions from the repo root manifests.

    Returns {language: version} with language keys 'go' / 'python' /
    'node'. Degrades to {} on anything unreadable/unparseable/non-grammar
    — NEVER raises (a raise at the call site would abort the whole
    dynamic-test step before any finding is tested).
    """
    declared: dict[str, str] = {}
    if not repo_path:
        return declared
    root = Path(repo_path)

    def _first(paths, parse):
        for rel in paths:
            text = _read_bounded(root / rel)
            if text is not None:
                v = parse(text)
                if v:
                    return v
        return None

    go = _first(("go.mod",), _from_go_mod)
    # A chosen interpreter takes precedence over a compatibility floor.
    py = (_first((".python-version",), _from_python_version)
          or _first(("pyproject.toml",), _from_pyproject))
    node = _first(("package.json",), _from_package_json)

    tools = _first((".tool-versions",), _from_tool_versions) or {}
    go = go or tools.get("golang")
    py = py or tools.get("python")
    node = node or tools.get("nodejs") or tools.get("node")

    if go:
        declared["go"] = go
    if py:
        declared["python"] = py
    if node:
        declared["node"] = node
    return declared
