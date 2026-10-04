# Security and sensitive reports

Atlas Core is an experimental public preview. The current development version
and published 1.0.0rc2 baseline have limited synthetic checks, not a production
security qualification or a promise of maintained historical versions.

## Reporting

GitHub private vulnerability reporting is enabled for this repository. For a
sensitive report, use [Report a vulnerability](https://github.com/joeldfarrington/atlas-ai-core/security/advisories/new)
from the repository's Security tab. GitHub requires sign-in and notifies the
maintainer when you submit a private report. The reporter becomes a collaborator
on that proposed advisory; this does not grant repository administration.

Keep sensitive details out of public issues. Do not send actual credentials,
personal data or private system artifacts through the report; use a minimal
synthetic reproduction. Ordinary public bugs can use the bug template with
synthetic inputs. The reporting setting does not publish an advisory or promise
a response or remediation deadline.

Useful private reports identify the public commit,
affected component, expected boundary, observed behavior, realistic impact and
a minimal synthetic reproduction. Do not include secret values or unnecessary
personal files. Response and remediation times are not guaranteed.

## Boundaries and known limitations

Relevant boundaries include owner-controlled tool authorization, approval/run
binding, filesystem and private-state separation, backup handling, model/tool
inputs, and dependency behavior. Report a plausible boundary failure with its
reachability and impact; a passing mock test is not grounds to dismiss it.

Default execution is denied and live providers, native workers, connectors and
supervisors are disabled. The owner-file prototype remains **blocked from live
use with real credentials** until child-process credential inheritance is
addressed and reviewed; see [PRIVATE_SETTINGS.md](PRIVATE_SETTINGS.md).

Same-user hostile-process protection, process crash/restart recovery, in-flight
revocation, installer rollback, UI rendering and native/live provider behavior
remain unqualified. These are testing limitations, not automatic exclusions or
accepted-risk declarations. No new severity rules or finding suppressions are
introduced by this document.
