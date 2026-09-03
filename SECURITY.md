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

Out of scope: the hosted instance at `oauth-server-ts.fly.dev` beyond what a request to a public
endpoint reveals (it is a production deployment, not a test target); denial of service by volume;
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

## What operators should know

The contact above is the project's. A self-hosted deployment advertises it at
`/.well-known/security.txt` so that a defect in this software reaches the people who can fix it.
An operator who prefers their own contact on their own domain can serve the file from the proxy in
front of this server; the server does not currently make the contact configurable.
