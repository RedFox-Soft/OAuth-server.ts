# Security Policy

OAuth-server.ts is an authorization server; a defect in it is a defect in every deployment's front
door. Reports are welcome, and they are taken seriously.

## Reporting a vulnerability

Email **security@foxauth.dev**. Do not open a public issue for anything you believe is a
vulnerability.

Please include the version or commit, the endpoint or component, steps to reproduce, and what you
believe the impact is. A proof of concept helps; an exploit against a deployment you do not own is
not needed and not wanted.

You will receive an acknowledgement within three business days. We aim to confirm or rule out the
report within ten business days, and to ship a fix for a confirmed vulnerability within ninety days
of the report. You will be told when the fix is released, and credited in the release notes unless
you ask not to be.

Every instance also serves this contact at `/.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)).

## Scope

In scope: the server code in this repository — the protocol endpoints, the end-user screens, the
administration console and its API, the MCP control plane, the storage adapters, the Docker image
and the deployment configuration we ship.

Out of scope: the hosted instances at `auth.foxauth.dev` and `conformance.foxauth.dev` beyond what a
request to a public endpoint reveals — the first is a production deployment and neither is a test
target, and the second is configured for whichever profile the OpenID conformance suite is exercising,
so a setting it has on or off is a test plan's requirement rather than a claim about the software;
denial of service by volume;
findings that require a compromised administrator account or a compromised database; reports
against third-party dependencies without a demonstrated effect on this server.

## Supported versions

Security fixes are released for the latest minor version. Until 1.0, that means the latest `0.x`
release; a fix is not backported to an earlier `0.x`.

## Safe harbour

Research conducted in good faith and within this policy — no data exfiltration beyond what is
needed to demonstrate the issue, no disruption of other users, no public disclosure before a fix
is available or ninety days have passed, whichever comes first — will not lead to legal action
from us.

## Assurance

What this project can show for its security, and what it cannot yet. Both lists are kept honest on
purpose: a claim here that the repository does not back is itself a defect, and you may report it.

What exists:

- **A published threat model** — [foxauth.dev/docs/security/threat-model](https://foxauth.dev/docs/security/threat-model/)
  names the assets, the trust boundaries and the attackers this server is built against, and for
  each threat the control in this repository that answers it and the test that holds the control.
- **Automated scanning on every push, every pull request and every week** — the
  [Security workflow](https://github.com/RedFox-Soft/OAuth-server.ts/actions/workflows/security.yml)
  runs CodeQL over the TypeScript and over the workflows themselves, audits both Bun lockfiles and
  fails on a high or critical advisory, reviews the dependencies a pull request adds, and scans the
  published container image. Run logs are public; findings land in the repository's code scanning
  alerts. [foxauth.dev/docs/security/assurance](https://foxauth.dev/docs/security/assurance/)
  describes each check and where to read its result.
- **Signed images, with an SBOM and build provenance** — every image the
  [Release workflow](https://github.com/RedFox-Soft/OAuth-server.ts/actions/workflows/release.yml)
  publishes is signed with `cosign` over its digest, keyless, so the signature is verified against a
  short-lived certificate naming this repository, this workflow and the version tag rather than
  against a key we ask you to trust. The same image carries an SBOM of every package inside it and a
  full build record, and a signed SLSA provenance statement is filed in a public transparency log.
  The release's own assets — the changelog and the generated reference tables — carry a provenance
  statement of their own, attached to the release so a download can be checked on its own terms.
  The commands to check all of it yourself are on
  [foxauth.dev/docs/security/assurance](https://foxauth.dev/docs/security/assurance/#the-released-image-and-how-to-check-it-is-ours).
  A signature says where the image came from and nothing about whether the code in it is any good;
  its worth is that it makes everything else on this page evidence about the artifact you are
  actually running.

- **An OpenSSF Scorecard**, published weekly by the
  [Scorecard workflow](https://github.com/RedFox-Soft/OAuth-server.ts/actions/workflows/scorecard.yml)
  and readable at
  [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/RedFox-Soft/OAuth-server.ts) — an
  assessment of the repository's practices by checks we do not write.
- **Repository protections** — secret scanning with push protection, Dependabot alerts and security
  updates, and
  [private vulnerability reporting](https://github.com/RedFox-Soft/OAuth-server.ts/security/advisories/new)
  as an alternative to the email above.

What does not exist yet:

- **No external audit.** No third party has been paid to assess this code. When one is, the report
  is published on this page in full, findings included.
- **No paid bug bounty.** A confirmed report earns credit in the release notes and our thanks, not
  money. The scope and safe harbour above are the whole programme.
- **No OpenID Foundation certification.** The conformance suite has not been run against a release;
  standards compliance is asserted by this project's own test suite until it has.

## What operators should know

The contact above is the project's. A self-hosted deployment advertises it at
`/.well-known/security.txt` so that a defect in this software reaches the people who can fix it.
An operator who prefers their own contact on their own domain can serve the file from the proxy in
front of this server; the server does not currently make the contact configurable.
