# Private owner settings — candidate design and prototype

The working Atlas has not been modified. No credentials, account settings,
personal identity, memory database or live controls have been read for migration,
moved or copied. This candidate is a separate installation and defaults to an
empty, offline mock environment.

## File and data boundaries

- **Public candidate:** code, empty templates, generic identity, synthetic tests.
- **Owner settings:** an explicitly selected JSON file outside the repository,
  owned by the current POSIX user with mode `0600` or `0400`, single hard link,
  regular file, no symlink components, bounded size and an exact allowlist schema.
- **Private state:** a separately selected `0700` root outside the repository,
  containing `data/`, `identity/` and `workspace/`. It holds the SQLite database,
  personal memory/context and generated working files. It is not a source tree.
- **Credential store:** existing Google OS-keyring support stays disabled. A
  native OS-vault reference may be preferable to a plaintext file for long-lived
  credentials, but it needs a separately reviewed adapter and owner configuration.

The public `examples/owner-settings.example.json` contains only empty values.
The credential file must also remain outside the application state root; the
loader refuses that overlap so memory/workspace backups cannot absorb it.
If the owner later chooses this file approach, copy the template to an exact
approved private location, set private permissions, and fill it personally under
the migration approval. The in-repository template is deliberately refused by
the loader. Do not place a filled file anywhere in the repository.

The explicit pointer is `ATLAS_OWNER_FILE=/absolute/private/location/owner.json`.
The loader does not search home directories, discover credential files or read
the Keychain. `ATLAS_PRIVATE_ROOT` can be supplied directly for a credential-free
mock review. Personal identity is copied only as generic initial templates, and
existing files are never replaced.

Allowed private settings: `private_root`, `google_expected_account`, and
`google_time_zone`. Allowed secret names: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`ATLAS_API_TOKEN`, and `ATLAS_LOCAL_API_KEY`. OAuth refresh/client secrets and
arbitrary permission changes are not accepted by this schema. The existing
connector's separate secure-store flow must be reviewed if Google is desired.

## Failure behavior and limits

**Live use of this prototype with real credentials is blocked until a reviewed
scoped resolver or child-environment filter prevents credential inheritance.**
Publication of the code does not qualify or authorize real-secret use or migration.

Absent owner-file pointer: no file is discovered or read. Missing private state
for the sample: startup fails with `private_state_root_required`. A selected
file that is absent, malformed, too large, non-private, linked, contains unknown
fields, or changes during the read fails with a categorical error. Duplicate
keys and conflicting environment values are refused; the loader does not echo
file contents or fall back to an unrelated store. Empty credential values count
as missing. An enabled cloud provider without its required credential is refused
by the router before a request; the default providers remain disabled.

This is a POSIX prototype, not an encrypted vault or protection against a hostile
process running as the same OS user. Compatibility adapters consume process
environment entries. Loaded values therefore stay in that process environment
and could be inherited by child processes if execution were later enabled.
Default tools deny execution and live supervisors are disabled; reviewing an
explicit child-environment filter or a scoped vault-backed in-memory resolver is
required before enabling those features with real credentials. Diagnostics must
retain only names/presence, never values. A user can also deliberately configure
unsafe paths outside this prototype's repository boundary; approve exact roots
and do not target the working Atlas state.

## Exact future migration, verification and rollback gates

1. **Identify and freeze:** select the exact canonical application/version,
   configuration, owner policy and data roots with Joel. Record source hashes and
   privately identify the current worker/task state. Do not stop/reconfigure any
   live instance during this candidate preparation.
2. **Back up before change:** use Joel's approved private backup workflow. Obtain
   a consistent SQLite snapshot with its supported backup mechanism rather than
   copying a live database/WAL arbitrarily. Preserve identity, permissions,
   registry and required recovery state privately. Verify backup integrity and a
   disposable restoration before proceeding. Keep credentials out of ordinary
   application/public backups; any credential-file backup must have a separately
   approved encrypted destination and recovery method.
3. **Review mappings:** approve the exact new private owner-file path, state root,
   ownership/modes, permitted fields and chosen secure-store/file design. Joel
   supplies any actual values through the approved private method. Do not export
   existing Keychain items automatically, log values, or reset exhausted counters.
4. **Copy before cutover:** in an approved maintenance window, copy selected
   personal identity/memory into a new private root without deleting or changing
   the original. Preserve genuine owner controls and task lineage separately;
   the public foundation template is not a replacement for those adopted grants.
   Native/predecessor-bound controls need their own requalification after a path
   or runtime change. Never let two instances write to the same state root.
5. **Verify offline first:** confirm exact roots, permissions, source/config
   hashes, identity and record counts using private evidence, then run mock-only
   memory/backup/restore tests. Check missing-secret errors and that no private
   file is tracked or packaged. Validate credential presence without printing
   values. A real provider/connector canary needs a separate approved destination,
   data purpose, cost/egress scope and stop condition.
6. **Cut over only after approval:** present the tested new application/config
   hashes, backup/restore receipt, exact launcher change and rollback commands.
   Get Joel's explicit approval before the live loader/configuration or launcher
   changes. Keep the old installation and original state available and unchanged
   until the new instance's acceptance and retention decision are confirmed.
7. **Rollback:** stop only the new instance, quarantine its new state for private
   review, and return the launcher to the preserved old application/configuration
   and original state. Restore from the verified private backup only if required
   and authorized. Reconcile uncertain tasks before any replay. Do not delete the
   new or old data as part of automatic rollback.

Publication is a different approval. It covers only the reviewed public export,
not any real-secret migration, private-state transfer, live installation change,
account connection or new authority.
