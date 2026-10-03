# Third-party dependency disclosures

Atlas project material is licensed under Apache-2.0. Separately installed
components retain their original licenses. **Dependency code, virtual
environments, native libraries, optional SDKs, workers and model weights are not
bundled in this source ZIP, source distribution or Atlas wheel.**

A bounded review identified no explicit copied third-party source in the selected
Atlas files. Consequently, no third-party code license text was substituted for
Atlas's license or copied into this release as though its dependency code were
included. The full Apache text and Atlas copyright/attribution are in LICENSE
and NOTICE. Absence of a detected copy is not proof of original authorship.

## Observed dependency versions and licenses

The following default macOS/CPython 3.14.7 environment was reused read-only for
build and tests. There are 32 runtime distributions and 40 distributions including
development/build tools. DEPENDENCIES.json contains metadata/legal-file hashes,
upstream URLs and nested notice locations. These are observed versions, not a
cross-platform resolver lock or an exhaustive binary-component SBOM.

| Distribution | Observed version | Role | License declaration or verified local text |
|---|---|---|---|
| annotated-doc | 0.0.5 | runtime | MIT |
| annotated-types | 0.8.0 | runtime | MIT |
| anyio | 4.14.2 | runtime | MIT |
| build | 1.5.0 | development | MIT |
| certifi | 2026.7.22 | runtime | MPL-2.0 |
| cffi | 2.1.1 | runtime | MIT-0 |
| click | 8.5.0 | runtime | BSD-3-Clause |
| cryptography | 50.0.1 | runtime | Apache-2.0 OR BSD-3-Clause |
| fastapi | 0.141.1 | runtime | MIT |
| h11 | 0.16.0 | runtime | MIT |
| httpcore | 1.0.9 | runtime | BSD-3-Clause |
| httpx | 0.28.1 | runtime | BSD-3-Clause |
| idna | 3.19 | runtime | BSD-3-Clause |
| iniconfig | 2.3.0 | development | MIT |
| jaraco.classes | 3.4.0 | runtime | MIT (observed local license text) |
| jaraco.context | 6.1.2 | runtime | MIT |
| jaraco.functools | 4.6.0 | runtime | MIT |
| keyring | 25.7.0 | runtime | MIT |
| markdown-it-py | 4.2.0 | runtime | MIT (observed local license text) |
| mdurl | 0.1.2 | runtime | MIT (observed local license text) |
| more-itertools | 11.1.0 | runtime | MIT |
| packaging | 26.3 | build, development | Apache-2.0 OR BSD-2-Clause |
| pluggy | 1.6.0 | development | MIT |
| pycparser | 3.0 | runtime | BSD-3-Clause |
| pydantic | 2.13.4 | runtime | MIT |
| pydantic_core | 2.46.4 | runtime | MIT |
| Pygments | 2.21.0 | development, runtime | BSD-2-Clause |
| pyproject_hooks | 1.2.0 | development | MIT (observed local license text) |
| pytest | 9.1.1 | development | MIT |
| python-multipart | 0.0.32 | runtime | Apache-2.0 |
| PyYAML | 6.0.3 | runtime | MIT |
| rich | 15.0.0 | runtime | MIT |
| setuptools | 84.0.0 | build | MIT |
| shellingham | 1.5.4 | runtime | ISC License |
| starlette | 1.6.0 | runtime | BSD-3-Clause |
| typer | 0.27.1 | runtime | MIT |
| typing_extensions | 4.16.0 | runtime | PSF-2.0 |
| typing-inspection | 0.4.4 | runtime | MIT |
| uvicorn | 0.52.4 | runtime | BSD-3-Clause |
| wheel | 0.48.0 | build | MIT |

## Nested material that top-level labels do not fully describe

- Typer includes a distinct Click/Pallets BSD-3-Clause notice at
  `typer/_click/LICENSE.txt`.
- markdown-it-py preserves the original markdown-it MIT notice at
  `markdown_it_py-4.2.0.dist-info/licenses/LICENSE.markdown-it`.
- mdurl's LICENSE explicitly attributes part of its URL parser to Node.js/Joyent
  and retains that MIT notice alongside the implementation notices.
- typing-extensions' complete LICENSE contains PSF license/history and additional
  incorporated-code notices. Its GPL compatibility discussion is not a GPL
  declaration for Atlas.
- The separately installed setuptools build tool contains validate-pyproject
  MPL-2.0 schemas/generated validation and fastjsonschema BSD-3-Clause notices in
  `setuptools/config/NOTICE` and `setuptools/config/_validate_pyproject/NOTICE`.
  Its vendored autocommand 2.2.2 legal file contains LGPLv3 text. Those tooling
  components are not embedded in Atlas output. Other setuptools vendor legal
  files are listed in DEPENDENCIES.json; the tool's MIT top-level label is not a
  substitute for them.
- Certifi declares MPL-2.0. Copying or redistributing its covered files can require
  preserved notices and source availability. Its separate installation does not
  relicense Atlas's independently owned project files.
- Cryptography 50.0.1 documents statically linked platform wheels. Embedded
  OpenSSL/Rust/native components and their exact versions/licenses were not fully
  inventoried. No cryptography or other native binary is bundled here.

## Obligations when distribution changes

If a downstream distributor bundles dependencies, a wheelhouse, build tools,
container or app installer, it must review the actual included artifacts and
preserve all applicable upstream copyright, license and attribution notices,
provide required source/availability information, and document changes where
required. Atlas's license does not waive these obligations. Do not use a
single top-level SPDX label as a substitute for nested legal files.

Changing operating system/Python versions, enabling extras, copying source,
adding optional SDKs/workers or distributing model weights requires another
component and license review. Optional Aider/OpenHands license strings in
compatibility code are declarations only; those artifacts are excluded,
disabled and unqualified by this release.

Primary guidance: [MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/),
[Apache License section 4](https://www.apache.org/licenses/LICENSE-2.0), and
[Cryptography 50.0.1 installation documentation](https://cryptography.io/en/50.0.1/installation/).
