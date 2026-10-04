# Release provenance

Copyright 2026 Joel Farrington. Licensed under Apache-2.0; see LICENSE and NOTICE.
The release maintainer confirmed authority to release the included code and
approved Apache-2.0 and this copyright attribution on October 3, 2026.

## Published 1.0.0rc2 baseline

The original release candidate was published on October 3, 2026 as public root
commit `97b7c0e30153ca3a9ef1b77ce69c9c5e096361b5`, containing 204 files.
Its licensed source ZIP SHA-256 is
`22d6c593f570396a502d8e444db3d537cea728c7ac84b7a5c837e5ad15ec04a4`.
Its checksum manifest SHA-256 is
`7ce8c7b96cce680d5bd48ff1155138382608d86510dc25cb01b1cb9ffa8399f5`.
Those hashes identify the original reviewed artifacts, not later working trees.

That release is derived from the previously reviewed, frozen 200-file export
whose ZIP SHA-256 is
`6228435a843d754f6b5a0d117194680ddca2a189661718bb9ada8efb606d29b1`.
That earlier artifact was an unlicensed private review package, not a published
release. This candidate has its own manifest and package hashes.

Changes from that snapshot are licensing/copyright/notices, public release
documentation, dependency disclosures, package metadata, and the package version
identifier. Runtime logic, default configuration, selected tests, UI and runtime
resources are retained from the frozen snapshot. No later live-source changes
were incorporated. The checksum manifest excludes its own checksum entry.

Local Git ancestry does not establish ownership. Some reviewed working-source
files were outside the local pinned history; that fact is not evidence of
third-party ownership. Review found no explicit copied third-party source origin
in the selected Atlas files. This is a bounded provenance/heuristic review, not
proof of original authorship or a certification that all secrets are absent.

The export includes only selected Atlas code, browser assets, synthetic fixtures,
generic identity/configuration templates, tests and release documentation. It
excludes private Git history, credentials, personal state, private project
registries, owner grants, commercial-project sources, native/iOS/signing assets,
unreviewed SDKs/workers/model weights and bundled dependency distributions.

Dependencies are installed separately and keep their original licenses. The
observed environment and nested notices are described in THIRD_PARTY_NOTICES.md
and DEPENDENCIES.json. A future dependency bundle, container, platform change,
optional backend or copied snippet requires its own attribution/license review.

Mock-only defaults do not qualify live providers, native execution, personal
migration or installation over an existing Atlas. In particular, the private
owner-file prototype remains blocked from live use with real credentials pending
protection against inheritance by child processes. See PRIVATE_SETTINGS.md.

The maintainer's Codex for Open Source application was submitted on October 4,
2026, using bounded evidence from the published 1.0.0rc2 baseline. Submission
does not establish acceptance or sponsorship.

## Unreleased 1.0.0rc3.dev0 maintenance preview

This development version updates public documentation, contribution/reporting
guidance, and automated checks. The application runtime changes only its version
identifier. Existing configurations, runtime logic, UI, resources and selected
tests are unchanged from the published baseline. No private source refresh or
private history import is performed.

`RELEASE_MANIFEST.sha256` describes the current reviewed public source tree,
excluding the manifest itself. After an intentional file change, stage only the
reviewed public paths and refresh it using `scripts/check_public_release.py` as
documented in DEVELOPMENT.md. The original rc2 manifest remains available at
its immutable baseline commit. New development builds use `1.0.0rc3.dev0` and
must not be labeled or distributed as the original rc2 artifacts.

Build checks compare source/sdist/wheel contents and licensing metadata with the
current manifest. They do not prove identical archive bytes across platforms or
produce a published release. Tags, GitHub Releases and registry uploads remain
separate maintainer decisions after the exact commit and checks are reviewed.
