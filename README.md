# axios-compromise-scan

Cross-platform scanner for exact matches to known compromised Node package versions in manifests, lockfiles, and installed package metadata.

Default targets:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`

The scanner works on macOS, Linux, and Windows and can scan a single repo, multiple roots, or a full machine path when explicitly requested.

## Files

- `scripts/scan_compromised_versions.py`: scanner
- `SKILL.md`: Codex skill entrypoint
- `CLAUDE.md`: Claude Code instructions
- `references/incident-2026-03-31.md`: source notes for the default targets

## Usage

macOS/Linux:

```bash
python3 scripts/scan_compromised_versions.py /path/to/repo
python3 scripts/scan_compromised_versions.py /path/one /path/two
python3 scripts/scan_compromised_versions.py --json /
python3 scripts/scan_compromised_versions.py --fail-on-match /path/to/repo
```

Windows PowerShell:

```powershell
py scripts\scan_compromised_versions.py C:\src\repo
py scripts\scan_compromised_versions.py --json C:\
```

Custom target set:

```bash
python3 scripts/scan_compromised_versions.py \
  --no-default-targets \
  --target package-a@1.2.3 \
  --target package-b@4.5.6 \
  /path/to/scan
```

## What It Scans

- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `yarn.lock`
- `pnpm-lock.yaml`
- `bun.lock`
- `bun.lockb`
- installed package `package.json` files under `node_modules`

## Result Types

- `manifest:*`: declared dependency spec in `package.json`
- `installed-package`: installed package manifest, usually under `node_modules`
- `lockfile:*`: exact resolved version in a lockfile
- `lockfile:bun.lockb`: best-effort binary-string match

## Notes

- The scan reports exact matches, not approximate or range-based risk.
- Full-system scans use platform-aware pruning to skip common OS-managed temp or virtual filesystem locations.
- If you install this as a local skill via the current `skill-installer`, do not use `--path .`; that installer path currently sparse-checks out only top-level files for repo-root installs.
