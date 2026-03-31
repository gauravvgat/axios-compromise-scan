---
name: axios-compromise-scan
description: Scan Node.js dependency manifests and lockfiles for compromised package versions, with defaults for the March 31, 2026 axios/plain-crypto-js incident. Use when Codex needs to check a repository, workspace, CI checkout, or a broader filesystem path on macOS, Linux, or Windows for known bad versions in package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, bun.lockb, or installed package manifests under node_modules.
---

# Axios Compromise Scan

## Overview

Use the bundled scanner to search one or more filesystem roots for exact package-version matches. The script is cross-platform and can also be called from other agents such as Claude Code. Default targets:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.0`
- `plain-crypto-js@4.2.1`

Read [references/incident-2026-03-31.md](references/incident-2026-03-31.md) when the user asks why those targets were chosen, when you need the IOC list, or when the default incident scope needs to be updated.

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

5. Add release-age guardrails for future installs when the user wants hardening.

```bash
python3 scripts/apply_release_age_guards.py
```

- This adds `min-release-age=7` to `~/.npmrc` if that key is not already present.
- This adds `exclude-newer = "7 days"` to the user uv config if that key is not already present.
- If the local npm CLI does not recognize `min-release-age`, upgrade npm first and then apply the guardrails.

6. Use the built-in IOC hunt during incident response.

- The scanner always checks current-platform filesystem IOC paths from the incident reference.
- If package hits are found, also use the reference file to hunt for the C2 domain `sfrclak.com`, campaign ID `6202033`, and the compromised maintainer metadata in package logs, npm metadata, EDR, proxy logs, and shell history.

## Interpreting Results

- Treat `manifest:*` hits as declared dependency specs in a `package.json`.
- Treat `installed-package` hits as an already-installed package manifest, usually under `node_modules`.
- Treat `lockfile:*` hits as an exact resolved version in a lockfile.
- Treat `lockfile:bun.lockb` hits as best-effort binary-string matches and verify them with a second check if they are critical.
- Treat `ioc:file-path` hits as host-level indicators of compromise from the March 31, 2026 incident.

When reporting back:

- State the scan scope.
- State whether the results are exact matches or nearby safe versions.
- If there are no hits, say so explicitly.
- If there are hits, list the exact file paths and explain whether they are manifests, installed packages, or lockfiles.
- For real-world scans, if any default target is found, assume the machine or environment is compromised ("pwned"): stop using it, shut it down, and take it to IT or security immediately.

## Notes

- Prefer the script over ad hoc grep so the result is reproducible.
- The script uses platform-aware pruning so full-system scans behave sensibly on macOS, Linux, and Windows.
- The hardening helper preserves existing config files and leaves existing npm and uv guardrail keys untouched.
- Keep the default target list in the script and the incident reference aligned.
- Update `agents/openai.yaml` if the skill’s UI-facing behavior changes materially.
