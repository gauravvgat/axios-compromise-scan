Use the bundled scanner script directly when asked to check a repository, workspace, CI checkout, or a wider filesystem path for compromised Node package versions.

Default targets:

- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`

Prefer the narrowest useful scope first.

- Repo scan: `python3 scripts/scan_compromised_versions.py /path/to/repo`
- Multi-root scan: `python3 scripts/scan_compromised_versions.py /path/one /path/two`
- JSON output: `python3 scripts/scan_compromised_versions.py --json /path/to/scan`
- CI/blocking mode: `python3 scripts/scan_compromised_versions.py --fail-on-match /path/to/scan`
- Custom targets: `python3 scripts/scan_compromised_versions.py --no-default-targets --target package@version /path/to/scan`

Platform notes:

- Linux and macOS: scan repo roots or `/` when explicitly asked for a full-system search.
- Windows PowerShell: `py scripts\\scan_compromised_versions.py C:\\path\\to\\repo`
- The script is path-separator agnostic and includes platform-aware pruning for full-drive scans.

Interpret results as follows:

- `manifest:*`: declared dependency spec in `package.json`
- `installed-package`: installed package manifest, usually under `node_modules`
- `lockfile:*`: exact resolved version in a lockfile
- `lockfile:bun.lockb`: best-effort binary-string match; verify critical hits with a second check

For real-world scans, if any of the default compromised versions are found, assume the machine or environment is compromised ("pwned"): stop using it, shut it down, and hand it to IT or security immediately.
