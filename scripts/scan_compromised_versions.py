#!/usr/bin/env python3
"""Scan dependency manifests and lockfiles for compromised package versions."""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import platform
import posixpath
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

DEFAULT_TARGETS = [
    ("axios", "1.14.1"),
    ("axios", "0.30.4"),
    ("plain-crypto-js", "4.2.1"),
]

TARGET_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
}

PRUNED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".Trash",
    "__pycache__",
    "build",
    "coverage",
    "dist",
}

PRUNED_ABSOLUTE_PREFIXES_BY_PLATFORM = {
    "Darwin": (
        "/System",
        "/Volumes",
        "/dev",
        "/proc",
        "/tmp",
        "/private/tmp",
        "/private/var/tmp",
    ),
    "Linux": (
        "/dev",
        "/proc",
        "/sys",
        "/tmp",
        "/run",
        "/var/tmp",
    ),
}

WINDOWS_PRUNED_BASENAMES = {
    "$recycle.bin",
    "system volume information",
}

WINDOWS_PRUNED_SUFFIXES = {
    ("windows", "temp"),
}


@dataclass(order=True)
class Match:
    package: str
    version: str
    kind: str
    path: str
    detail: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan manifests and lockfiles for exact compromised package versions."
    )
    parser.add_argument(
        "roots",
        nargs="*",
        default=["."],
        help="Filesystem roots to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="PACKAGE@VERSION",
        help="Override or extend the default targets. Repeat as needed.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of text.",
    )
    parser.add_argument(
        "--fail-on-match",
        action="store_true",
        help="Exit non-zero when at least one match is found.",
    )
    parser.add_argument(
        "--no-default-targets",
        action="store_true",
        help="Ignore the built-in target list and use only --target values.",
    )
    return parser.parse_args()


def parse_target(raw: str) -> tuple[str, str]:
    package, separator, version = raw.rpartition("@")
    if not separator or not package or not version:
        raise ValueError(f"Invalid target {raw!r}. Expected PACKAGE@VERSION.")
    return package, version


def compile_targets(args: argparse.Namespace) -> list[tuple[str, str]]:
    targets = [] if args.no_default_targets else list(DEFAULT_TARGETS)
    for raw in args.target:
        targets.append(parse_target(raw))
    deduped: list[tuple[str, str]] = []
    seen = set()
    for target in targets:
        if target not in seen:
            seen.add(target)
            deduped.append(target)
    return deduped


def normalize_path(path: str, system_name: str | None = None) -> str:
    system_name = system_name or platform.system()
    if system_name == "Windows":
        if os.name == "nt":
            path = os.path.realpath(path)
        return ntpath.normcase(ntpath.normpath(path))
    if os.name != "nt":
        path = os.path.realpath(path)
    return os.path.normcase(posixpath.normpath(path))


def path_parts(path: str, system_name: str) -> tuple[str, ...]:
    if system_name == "Windows":
        pure_path = PureWindowsPath(path)
    else:
        pure_path = PurePosixPath(path)
    return tuple(part.casefold() for part in pure_path.parts if part)


def should_prune_path(path: str, system_name: str | None = None) -> bool:
    system_name = system_name or platform.system()
    normalized = normalize_path(path, system_name)

    if system_name == "Windows":
        parts = path_parts(normalized, system_name)
        if not parts:
            return False
        if parts[-1] in WINDOWS_PRUNED_BASENAMES:
            return True
        return any(parts[-len(suffix) :] == suffix for suffix in WINDOWS_PRUNED_SUFFIXES)

    prefixes = tuple(
        normalize_path(prefix, system_name)
        for prefix in PRUNED_ABSOLUTE_PREFIXES_BY_PLATFORM.get(system_name, ())
    )
    return any(
        normalized == prefix or normalized.startswith(prefix + os.sep) for prefix in prefixes
    )


def iter_candidate_files(roots: list[str]) -> tuple[list[Path], list[str]]:
    candidates: list[Path] = []
    warnings: list[str] = []
    seen: set[str] = set()
    system_name = platform.system()

    for raw_root in roots:
        root = Path(raw_root).expanduser()
        if not root.exists():
            warnings.append(f"missing-root:{root}")
            continue

        resolved_root = Path(normalize_path(str(root), system_name))
        if resolved_root.is_file():
            if resolved_root.name in TARGET_FILE_NAMES:
                resolved_text = str(resolved_root)
                if resolved_text not in seen:
                    seen.add(resolved_text)
                    candidates.append(resolved_root)
            continue

        for current_root, dir_names, file_names in os.walk(
            resolved_root, topdown=True, followlinks=False
        ):
            if current_root != str(resolved_root) and should_prune_path(
                current_root, system_name
            ):
                dir_names[:] = []
                continue

            next_dirs = []
            for dir_name in dir_names:
                child = os.path.join(current_root, dir_name)
                if dir_name in PRUNED_DIR_NAMES:
                    continue
                if should_prune_path(child, system_name):
                    continue
                next_dirs.append(dir_name)
            dir_names[:] = next_dirs

            for file_name in file_names:
                if file_name not in TARGET_FILE_NAMES:
                    continue
                candidate = Path(current_root, file_name)
                candidate_text = str(candidate)
                if candidate_text in seen:
                    continue
                seen.add(candidate_text)
                candidates.append(candidate)

    return candidates, warnings


def add_match(
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
    package: str,
    version: str,
    kind: str,
    path: Path,
    detail: str,
) -> None:
    item = Match(package, version, kind, str(path), detail)
    key = (item.package, item.version, item.kind, item.path, item.detail)
    if key not in seen:
        seen.add(key)
        matches.append(item)


def version_in_spec(spec: str, version: str) -> bool:
    return bool(re.search(rf"(?<![0-9]){re.escape(version)}(?![0-9])", spec))


def scan_package_manifest(
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        data = json.load(handle)

    name = data.get("name")
    version = data.get("version")
    if isinstance(name, str) and isinstance(version, str):
        for target_package, target_version in targets:
            if name == target_package and version == target_version:
                add_match(
                    matches,
                    seen,
                    target_package,
                    target_version,
                    "installed-package",
                    path,
                    "package.json name/version",
                )

    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "resolutions",
        "overrides",
    ):
        dependency_map = data.get(section)
        if not isinstance(dependency_map, dict):
            continue
        for target_package, target_version in targets:
            spec = dependency_map.get(target_package)
            if isinstance(spec, str) and version_in_spec(spec, target_version):
                add_match(
                    matches,
                    seen,
                    target_package,
                    target_version,
                    f"manifest:{section}",
                    path,
                    f"{section} spec: {spec}",
                )


def walk_dependency_tree(
    dependency_map: object,
    prefix: str,
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    if not isinstance(dependency_map, dict):
        return

    for package_name, meta in dependency_map.items():
        if isinstance(meta, dict):
            version = meta.get("version")
            if isinstance(version, str):
                for target_package, target_version in targets:
                    if package_name == target_package and version == target_version:
                        add_match(
                            matches,
                            seen,
                            target_package,
                            target_version,
                            f"lockfile:{path.name}",
                            path,
                            f"{prefix}.{package_name}.version",
                        )
            walk_dependency_tree(
                meta.get("dependencies"),
                f"{prefix}.{package_name}.dependencies",
                path,
                targets,
                matches,
                seen,
            )


def scan_package_lock(
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        data = json.load(handle)

    packages = data.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str):
                continue
            for target_package, target_version in targets:
                if version != target_version:
                    continue
                pattern = rf"(?:^|node_modules/){re.escape(target_package)}$"
                if re.search(pattern, package_path):
                    add_match(
                        matches,
                        seen,
                        target_package,
                        target_version,
                        f"lockfile:{path.name}",
                        path,
                        f"packages[{package_path!r}].version",
                    )

    walk_dependency_tree(
        data.get("dependencies"),
        "dependencies",
        path,
        targets,
        matches,
        seen,
    )


def scan_yarn_lock(
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()

    index = 0
    while index < len(lines):
        line = lines[index]
        if line and not line.startswith((" ", "\t", "\n")) and line.rstrip().endswith(":"):
            header = line.rstrip()
            block = [header]
            index += 1
            while index < len(lines) and (
                lines[index].startswith((" ", "\t")) or not lines[index].strip()
            ):
                block.append(lines[index].rstrip("\n"))
                index += 1

            for target_package, target_version in targets:
                if f"{target_package}@" not in header:
                    continue

                version = None
                for block_line in block[1:]:
                    match = re.match(r'\s*version\s+["\']([^"\']+)["\']', block_line)
                    if match:
                        version = match.group(1)
                        break
                    match = re.match(
                        rf'\s*resolution:\s+"{re.escape(target_package)}@[^:]+:{re.escape(target_version)}"',
                        block_line,
                    )
                    if match:
                        version = target_version
                        break

                if version == target_version:
                    add_match(
                        matches,
                        seen,
                        target_package,
                        target_version,
                        "lockfile:yarn.lock",
                        path,
                        f"entry: {header[:200]}",
                    )
        else:
            index += 1


def scan_pnpm_lock(
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
) -> None:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        text = handle.read()

    for target_package, target_version in targets:
        package_key = re.compile(
            rf"(^|\n)\s{{0,2}}(?:/)?{re.escape(target_package)}@{re.escape(target_version)}(?:[(:]|$)",
            re.MULTILINE,
        )
        if package_key.search(text):
            add_match(
                matches,
                seen,
                target_package,
                target_version,
                "lockfile:pnpm-lock.yaml",
                path,
                "package key match",
            )
            continue

        importer_entry = re.compile(
            rf"(^|\n)\s+{re.escape(target_package)}:\s+.*(?<![0-9]){re.escape(target_version)}(?![0-9])",
            re.MULTILINE,
        )
        if importer_entry.search(text):
            add_match(
                matches,
                seen,
                target_package,
                target_version,
                "lockfile:pnpm-lock.yaml",
                path,
                "importer entry match",
            )


def scan_bun_lock_text(
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
    kind: str,
) -> None:
    with path.open("rb") as handle:
        text = handle.read().decode("utf-8", errors="ignore")

    for target_package, target_version in targets:
        pattern = re.compile(
            rf"{re.escape(target_package)}[^\n]{{0,160}}{re.escape(target_version)}|"
            rf"{re.escape(target_version)}[^\n]{{0,160}}{re.escape(target_package)}",
            re.IGNORECASE,
        )
        if pattern.search(text):
            add_match(
                matches,
                seen,
                target_package,
                target_version,
                kind,
                path,
                "text match",
            )


def scan_file(
    path: Path,
    targets: list[tuple[str, str]],
    matches: list[Match],
    seen: set[tuple[str, str, str, str, str]],
    warnings: list[str],
) -> None:
    try:
        if path.name == "package.json":
            scan_package_manifest(path, targets, matches, seen)
        elif path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            scan_package_lock(path, targets, matches, seen)
        elif path.name == "yarn.lock":
            scan_yarn_lock(path, targets, matches, seen)
        elif path.name == "pnpm-lock.yaml":
            scan_pnpm_lock(path, targets, matches, seen)
        elif path.name == "bun.lock":
            scan_bun_lock_text(path, targets, matches, seen, "lockfile:bun.lock")
        elif path.name == "bun.lockb":
            scan_bun_lock_text(path, targets, matches, seen, "lockfile:bun.lockb")
    except json.JSONDecodeError as error:
        warnings.append(f"json-parse-error:{path}:{error}")
    except OSError as error:
        warnings.append(f"read-error:{path}:{error}")


def render_text(
    roots: list[str],
    targets: list[tuple[str, str]],
    scanned_files: int,
    matches: list[Match],
    warnings: list[str],
) -> str:
    lines = []
    lines.append(f"roots: {', '.join(roots)}")
    lines.append(
        "targets: " + ", ".join(f"{package}@{version}" for package, version in targets)
    )
    lines.append(f"scanned_files: {scanned_files}")
    if matches:
        lines.append(f"matches: {len(matches)}")
        for match in matches:
            lines.append(
                f"- {match.package}@{match.version} [{match.kind}] {match.path} ({match.detail})"
            )
    else:
        lines.append("matches: 0")
        lines.append("No exact matches found.")
    if warnings:
        lines.append(f"warnings: {len(warnings)}")
        lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    try:
        targets = compile_targets(args)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2

    if not targets:
        print("No targets supplied.", file=sys.stderr)
        return 2

    candidate_files, warnings = iter_candidate_files(args.roots)
    matches: list[Match] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for path in candidate_files:
        scan_file(path, targets, matches, seen, warnings)

    matches.sort()

    if args.json:
        payload = {
            "roots": args.roots,
            "targets": [
                {"package": package, "version": version} for package, version in targets
            ],
            "scanned_files": len(candidate_files),
            "matches": [asdict(match) for match in matches],
            "warnings": warnings,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(args.roots, targets, len(candidate_files), matches, warnings))

    if args.fail_on_match and matches:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
