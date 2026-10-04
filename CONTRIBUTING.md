# Contributing to Atlas Core

Joel Farrington is the primary maintainer. This public project is a development
preview with selected synthetic tests and mock-only defaults. Small, explained
pull requests and reproducible bug reports are welcome; there is no guaranteed
response time or stable-release support commitment.

Start from a dedicated clone or fork of this public repository. Create a branch,
describe the problem and intended behavior, and follow [DEVELOPMENT.md](DEVELOPMENT.md)
for setup and checks. A draft pull request is useful while results or decisions
are pending. Include the exact commit, commands, results and untested limits.
Keep a failing test or synthetic reproduction when it helps demonstrate a fix.

Use fake inputs and temporary state outside the repository. Never attach real
credentials, settings files, private databases, backups, transcripts, customer
data or private project code to issues, commits or CI logs. See
[SECURITY.md](SECURITY.md) before reporting sensitive issues.

Preserve deny-by-default execution and disabled live integrations. A change that
enables a provider, uses real credentials, changes authority, or touches private
installation/state needs a separate reviewed scope. Passing mock tests does not
qualify crash recovery, in-flight revocation, installer rollback or native/live
behavior. Do not soften those limitations in documentation.

Before proposing copied code or a new dependency, identify its source, license
and required notices. Submit only work you have the right to contribute under
the repository's Apache-2.0 license. No separate CLA or license change is
introduced here. Update dependency disclosures when their reviewed scope changes.

Stage specific reviewed files, inspect the staged diff, refresh the public
manifest, and run the checks. A pull request should state why each file belongs
in the public export. Do not copy or push a live private Atlas checkout wholesale.
The maintainer reviews the diff and check results before deciding whether to
merge or release. Neither a PR nor passing CI automatically grants that decision.
