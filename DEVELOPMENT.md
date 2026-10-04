# Public development and release checks

## Separate checkout and state

Develop in a dedicated clone of the public repository. Its history starts at the
reviewed rc2 export; it is not the private installation or an automatic mirror.
Keep a virtual environment in `.venv` and synthetic application state in a new
private temporary directory outside the checkout. Do not supply owner files,
provider keys, OS-keyring connections or real Atlas state for these checks.

Python 3.11+ is declared. CI targets GitHub-hosted Ubuntu 24.04 on Python 3.11 and
3.14. The original rc2 review used macOS/Python 3.14.7. Other platforms and native
features remain unqualified. `constraints-tested.txt` pins the directly observed
packages; it is not a full transitive, cross-platform or hash-verified lock.
The legal disclosures describe the original observed dependency environment;
they are not an inventory of every future CI resolver result.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt '.[dev]' setuptools wheel
.venv/bin/python -m pip check
.venv/bin/python -I -B scripts/check_public_release.py manifest
.venv/bin/python -I -B scripts/check_public_release.py runtime
```

Installation downloads public dependencies. The runtime check then clears its
environment, uses temporary synthetic state, disables pytest plugin discovery,
and refuses network, subprocess and keyring API calls. It compiles/imports the
selected Atlas modules, runs the existing full synthetic suite (42 cases at the
rc2 baseline), and invokes the mock CLI in-process. It does not listen on a port,
launch a browser, qualify live Atlas, or constitute a hostile-code sandbox.

## Package checks

Build with the reviewed backend already installed, using a commit-derived epoch:

```sh
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
.venv/bin/python -m build --no-isolation
.venv/bin/python -I -B scripts/check_public_release.py packages
```

The package check rejects unexpected members, compares source/sdist/wheel
payloads against the manifest, and checks version/license metadata plus wheel
RECORD hashes. Build outputs in `dist/` are local checks, not published releases.
Do not attach development builds as rc2 assets or upload them to a registry.
These checks establish content consistency, not cross-platform bit-for-bit
archive reproducibility.

CI also runs the full suite against the extracted sdist and makes a separate
clean virtual environment for the built wheel. Its wheel check runs the existing
19 core cases, imports/compiles the package, checks the private-state boundary
using the selected public configuration, and invokes the same mock CLI. The
source-only owner-file cases are excluded from the wheel run because the wheel
does not package the repository-level configuration and templates.

Inspect the exact commit's Actions logs for Python/dependency versions, case
counts and package hashes. Failed or missing checks are unresolved; the workflow
definition itself is not a passing result. Public CI uses read-only repository
permissions, pinned action commits, hosted disposable runners and no supplied
secrets. No release/upload step or self-hosted Mac runner is configured.

## Updating the source manifest

The rc2 baseline and its old manifest are preserved at commit
`97b7c0e30153ca3a9ef1b77ce69c9c5e096361b5`. The current manifest covers all tracked
public source files except itself. After intentional changes, stage only the
reviewed paths, inspect the staged diff, then regenerate and stage the manifest:

```sh
git diff --cached
.venv/bin/python -I -B scripts/check_public_release.py manifest --write
git add RELEASE_MANIFEST.sha256
.venv/bin/python -I -B scripts/check_public_release.py manifest
git diff --cached --stat
```

`--write` reads the Git index's path inventory and hashes those files from the
working tree. Check that no unstaged changes remain for those paths before
committing; hashing a file does not approve it. The ordinary check refuses a
missing/mismatched entry, symlink or tracked file omitted from the manifest.

## Reconciliation with private development

Private development and public maintenance remain separate. For an approved
change from either side, select an explicit path allowlist and review the patch
against the receiving checkout's exact base. Review ownership/notices and scan
for credential/private-state references without printing their values. Copy or
apply only that reviewed diff into a fresh public branch, preserving concurrent
changes. Re-run public checks and refresh the manifest. Do not merge private
history, attach private artifacts, bulk-sync directories or add the private
checkout's remotes to this public workflow.

Record the public commit and its check results before any separately approved
private adoption. Public CI does not authorize modifying a working installation,
launcher, settings, credentials or data. Tags, GitHub Releases, registry uploads
and repository access/security-setting changes require separate maintainer
decisions. Review dependencies and notices again before bundling them or adding
an optional backend.
