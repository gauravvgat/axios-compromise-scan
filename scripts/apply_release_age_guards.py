#!/usr/bin/env python3
"""Add npm and uv release-age guardrails to the current user's config."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def _default_npmrc() -> Path:
    return Path.home() / ".npmrc"


def _default_uv_toml() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "uv" / "uv.toml"
        return Path.home() / "AppData" / "Roaming" / "uv" / "uv.toml"

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "uv" / "uv.toml"
    return Path.home() / ".config" / "uv" / "uv.toml"


def _append_setting_if_missing(path: Path, key: str, value: str) -> str:
    new_line = f"{key} = {value}" if value.startswith('"') else f"{key}={value}"
    if path.exists():
        original = path.read_text(encoding="utf-8")
    else:
        original = ""

    lines = original.splitlines(keepends=True)

    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith(f"{key}=") or stripped.startswith(f"{key} ="):
            return "kept-existing"

    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.append(new_line + "\n")

    updated_text = "".join(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated_text, encoding="utf-8")
    return "created" if not original else "updated"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add npm and uv release-age guardrails to user config files."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Minimum package age in days for npm and uv (default: 7).",
    )
    parser.add_argument(
        "--npmrc",
        type=Path,
        default=_default_npmrc(),
        help="Path to the npm config file (default: ~/.npmrc).",
    )
    parser.add_argument(
        "--uv-config",
        type=Path,
        default=_default_uv_toml(),
        help="Path to the uv config file (default: platform-specific user config).",
    )
    args = parser.parse_args()

    npm_state = _append_setting_if_missing(args.npmrc, "min-release-age", str(args.days))
    uv_state = _append_setting_if_missing(
        args.uv_config, "exclude-newer", f'"{args.days} days"'
    )

    print(f"{npm_state}: {args.npmrc}")
    print(f"{uv_state}: {args.uv_config}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
