# Security and sensitive reports

Atlas Core is an experimental public preview. The current development version
and published 1.0.0rc2 baseline have limited synthetic checks, not a production
security qualification or a promise of maintained historical versions.

## Reporting

No private reporting channel has been verified for this repository yet, and this
document does not claim that GitHub private vulnerability reporting is enabled.
For a sensitive report, first open an issue titled **Private security contact
requested**, with no technical details, attachments, personal data or secrets.
The maintainer must establish a private route before receiving the details.
Ordinary public bugs can use the bug template with a synthetic reproduction.
Never post credentials or a working exploit against a live/private system.

Once a private route is established, useful reports identify the public commit,
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
