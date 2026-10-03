# Atlas Core

Atlas Core contains a portable Python runtime and browser UI, neutral templates,
and a selected synthetic test suite. It is licensed under [Apache 2.0](LICENSE).
Copyright 2026 Joel Farrington. Developed with AI assistance.
See [NOTICE](NOTICE), [dependency disclosures](THIRD_PARTY_NOTICES.md), and
[release provenance](RELEASE_PROVENANCE.md).

Version **1.0.0rc2** is a release candidate prepared for final publication review.
It is based on a previously reviewed frozen export. Its Apache license decision
is approved; repository creation, publication and application submission still
require their separate final approval.

The candidate is separate from canonical Atlas. It does not contain its Git
history, personal memory, credentials, private project registry, owner adoption
records, iOS signing defaults, native artifacts or commissioning evidence. It
uses a reviewed current-source dependency closure rather than only tracked files.
Optional compatibility modules are retained because the current CLI/API imports
them; their execution paths remain disabled and unqualified in this candidate.

## Setup for a future owner-run review

Python 3.11+ is declared; checks so far used Python 3.14.7 on this Mac. This
candidate includes POSIX/macOS-specific compatibility modules. Other Python
versions and operating systems have not been verified. Dependencies and tools
are not bundled. `constraints-tested.txt` records the tested environment; it is
not a cross-platform hash lock. The dependency disclosure records observed
licenses and upstream notices for that environment, not a complete binary SBOM.

These are setup instructions, not commands performed against your working Atlas:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt '.[dev]'
export ATLAS_PRIVATE_ROOT="$HOME/.local/share/atlas-core-candidate"
mkdir -m 700 -p "$ATLAS_PRIVATE_ROOT"
.venv/bin/atlas chat "Hello" --config config/atlas.yaml --provider mock --no-tools --no-approvals
```

Choose a new private root outside the repository. Do not point it at existing
Atlas data, its live workspace, or a broad home directory. The loader requires a
private directory and creates empty data/workspace plus generic identity files;
it never overwrites existing identity. The mock is deterministic and does not
establish model quality, a live connection or autonomous operation.

All tools are denied by default. The registry is empty. Cloud providers, Google,
Mac operator, phone companion, practice and every supervisor are disabled. The
neutral foundation template creates no owner authority. No external model or
native worker/SDK has been installed or qualified by this export.

## Private settings and memory

No repository-local `.env` is automatically read. `ATLAS_OWNER_FILE` is an
explicit pointer to an optional owner-only JSON file outside the repository.
[PRIVATE_SETTINGS.md](PRIVATE_SETTINGS.md) describes its empty template, missing
credential behavior, limitations, and the owner-reviewed migration/rollback plan.
Never commit a filled settings file, private state, backup, transcript or token.
**The owner-file prototype is blocked from live use with real credentials until
credential inheritance by child processes is addressed and reviewed.** Its
process-environment compatibility mechanism is suitable only for the current
credential-free/synthetic review scope. Execution remains denied by default.

Cloud providers also require an owner-selected model, deliberate enablement and
the applicable data-egress permission. Missing credentials fail before a request
through the router. Empty template values do not enable any provider. The
existing Google connector's OS-keyring support is retained but disabled; no
credential store is configured or accessed by this preparation.

## Tests and UI

```sh
.venv/bin/python -m pytest tests -q
```

The release review used 42 synthetic unit tests for memory, mock runtime, tool
approval state, migration/backup round trips, adapter mocks and the private-file
boundary. It also compiled 169 Python files and imported 168 modules from the
candidate only. Test state lived outside this repository in a task-owned private
fixture. Ambient credentials were cleared; network/process/vault actions and
canonical payload reads were refused. No guard denial occurred in the passing
run. This is not the entire private Atlas acceptance suite or a security audit.
The unpacked wheel also passed 19 core tests plus an external-private-state
boundary check. The wheel and sdist were built offline and their members were
checked against the release file allowlist. Dependencies were reused read-only;
no clean dependency installation or online resolver run was performed.

UI assets are packaged, but no browser rendering or listening server was tested.
A future owner-run local UI review can use `atlas start --mock --no-browser`
after choosing private state. That command starts a local server and has not
been executed here. Live supervision, native/iOS behavior, actual provider calls,
personal-data migration and installation over working Atlas remain unverified
and require their separate approval/checks.

Do not publish this candidate until the exact file inventory, code changes,
license/notices, test results and repository settings receive Joel's review.
The canonical installation remains the recovery baseline throughout preparation.
