---
name: scan-compromised-package-versions
description: Scan Node.js dependency manifests and lockfiles for compromised package versions, with defaults for the March 31, 2026 axios/plain-crypto-js incident. Use when Codex needs to check a repository, workspace, CI checkout, or a broader filesystem path on macOS, Linux, or Windows for known bad versions in package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, bun.lockb, or installed package manifests under node_modules.
---

# Scan Compromised Package Versions

## Overview

Use the bundled scanner to search one or more filesystem roots for exact package-version matches. The script is cross-platform and can also be called from other agents such as Claude Code. Default targets:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`

Read [references/incident-2026-03-31.md](references/incident-2026-03-31.md) only when the user asks why those targets were chosen or when the default list needs to be updated.

## Workflow

1. Choose the narrowest useful scope first.

- Repository check: scan the repo root.
- Workspace check: scan one or more top-level project directories.
- Full machine check: scan `/` on macOS or Linux, or a drive root such as `C:\` on Windows, only when the user explicitly asks for a full-system search.

2. Run the scanner.

```bash
python3 scripts/scan_compromised_versions.py /path/to/repo
python3 scripts/scan_compromised_versions.py /Users/gaurav/Code /Users/gaurav/.nvm
python3 scripts/scan_compromised_versions.py --json /
```

```powershell
py scripts\scan_compromised_versions.py C:\src\repo
py scripts\scan_compromised_versions.py --json C:\
```

3. Override targets when needed.

```bash
python3 scripts/scan_compromised_versions.py \
  --target axios@1.14.1 \
  --target axios@0.30.4 \
  --target plain-crypto-js@4.2.1 \
  /path/to/scan
```

4. Use CI-style failure when the scan should block.

```bash
python3 scripts/scan_compromised_versions.py --fail-on-match /path/to/scan
```

## Interpreting Results

- Treat `manifest:*` hits as declared dependency specs in a `package.json`.
- Treat `installed-package` hits as an already-installed package manifest, usually under `node_modules`.
- Treat `lockfile:*` hits as an exact resolved version in a lockfile.
- Treat `lockfile:bun.lockb` hits as best-effort binary-string matches and verify them with a second check if they are critical.

When reporting back:

- State the scan scope.
- State whether the results are exact matches or nearby safe versions.
- If there are no hits, say so explicitly.
- If there are hits, list the exact file paths and explain whether they are manifests, installed packages, or lockfiles.

## Notes

- Prefer the script over ad hoc grep so the result is reproducible.
- The script uses platform-aware pruning so full-system scans behave sensibly on macOS, Linux, and Windows.
- Keep the default target list in the script and the incident reference aligned.
- Update `agents/openai.yaml` if the skill’s UI-facing behavior changes materially.
