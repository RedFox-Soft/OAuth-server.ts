# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Spec numbers refer to the (untracked) `specs/`
directories; open work is tracked as GitHub issues; full retrospectives live in the git history of
the retired `TASKS.md` and in the knowledge base at `wiki/`.

## [Unreleased]

### Added

- test: coverage for six properties the suite claimed and did not hold — the MongoDB secret round trip
  through the real BSON codec, the PostgreSQL document-column encoding, the timing of both
  constant-time secret comparisons, the discovery document following `ISSUER` rather than a forwarded
  header, and every published agent tool having a route the dispatcher serves. Each was verified by
  reintroducing the defect and confirming the gate fails.

- storage: PostgreSQL is now a supported datastore alongside MongoDB. A deployment picks one by
  which connection string it sets — `POSTGRES_URL` or `MONGODB_URI` — and setting both is refused at
  startup rather than resolved by precedence, since a server that quietly chose the other database
  is indistinguishable from total data loss. `bun run db:setup:pg` provisions the schema and
  `--check` reports on it without writing; documents are stored as `jsonb`, and expired rows are
  reclaimed by a sweeper because PostgreSQL has no TTL index. Nothing above the storage layer
  changed, and existing MongoDB deployments are unaffected.
- storage: a schema-migration layer for both backends, applied by `bun run db:migrate` (`--plan` to
  gate a deploy). Migrations are declared as an ordered set with a checksum, recorded as they run,
  and serialised by a renewable lease so two replicas rolling at once cannot both apply a step. The
  server refuses to start against a database that is behind, ahead, or holding a record for a
  migration whose declaration has since changed. The one-off `managedBy → ownerGroupId` conversion
  has been retired rather than carried into it: a deployment predating ownership groups must upgrade
  through an earlier release first.
- ops: `GET /ready` joins `GET /health`, splitting "don't route to me" from "restart me". Liveness
  answers from the process alone and stays exempt from the rate limiter; readiness reaches the
  datastore, is metered as `public`, holds its last answer for a second so a probe storm cannot
  become database load, shares one outstanding probe rather than starting one per caller, and
  recovers on its own. The probe carries its own five-second deadline, because a driver's timeout
  bounds establishing a connection and not a query on one it already holds: measured against a
  database that was up, connected and no longer answering, an unbounded probe took 30 seconds to
  report anything. Pointing both probes at `/health` turns a database
  outage invisible, since the process is alive and the probe passes while requests keep arriving;
  pointing liveness at `/ready` restarts healthy processes for a database's outage. Both are the
  mistake this split exists to prevent.
- ops: two Fly configurations instead of one. `fly.toml` now describes a deployment that must always
  answer — machines are never stopped for want of traffic, deploys are blue-green so a single-machine
  release costs no downtime, and both probes are wired — while the new `fly.conformance.toml`
  describes a separate app for the OpenID conformance suite that stops when idle and keeps its own
  database. `ISSUER` and `DATABASE_NAME` moved out of secrets into each file's `[env]`, since neither
  is a credential and a config that names its own issuer lets the deploy workflow check the
  advertised one against it. The workflow takes the target as an input, and the release command now
  runs `db:migrate` after `db:setup` so a release carrying its first migration cannot deploy an image
  that refuses to boot.
- security: the release assets now carry provenance of their own. `docs-export.json` and the
  `CHANGELOG.md` a release ships are covered by a single signed SLSA v1 statement, produced the same
  keyless way as the image's and attached to the release as `release-assets.intoto.jsonl`, so a
  download can be verified without reaching back to GitHub for the statement; the release fails if
  the bundle it is about to attach does not verify. The previous argument — that documentation
  nobody executes needs no signature — held for the changelog but not for reference data another
  project's build reads, which is worth a statement naming the commit and the run behind it.

### Fixed

- jwks: key generation offers every asymmetric signing algorithm the server knows — `RS256`/`384`/
  `512`, `PS256`/`384`/`512`, `ES256`/`384`/`512`, `EdDSA` and `Ed25519` — in the console and through
  the agent tool, read from the algorithm register rather than restated beside it. It offered only the
  three RSA `RS*` algorithms, which meant a FAPI 2.0 deployment could not be assembled through this
  server's own management surface at all: the profile requires PS256 or ES256, and the operator had to
  write a key straight into the key store. An existing RSA key is still not made to sign PS256 —
  RFC 7517 §4.4 makes a key's `alg` the algorithm it is intended for, and honouring a key past its
  declared intent would let a deployment that pinned a key to one algorithm quietly use another.
  Generating the key you need is the route. The key page also now says when a generated algorithm is
  not yet advertised: discovery's algorithm lists are built at startup, so such a key signs
  immediately but no client asks for it until a restart — previously the page reported no restart
  required, which was true of the key and misleading about the deployment.

- userinfo: the access token may be presented in a form-encoded POST body, which OpenID Connect Core
  §5.3.1 describes alongside the header form. The body form is honoured only under the conditions
  RFC 6750 §2.2 attaches — a POST whose body is form-encoded — and a request that uses both methods
  at once is refused with the `invalid_request` §3.1 specifies; the query-parameter form of §2.3 is
  still not implemented, since OAuth 2.1 removes it and a token in a URL reaches access logs and
  browser history. A DPoP-bound token cannot be presented this way, because RFC 9449 defines no body
  form for it. Two consequences of the same change: a request carrying no credential at all is still
  answered with the bare RFC 6750 §3 challenge, now raised by the handler rather than by the header
  schema, which can no longer require the header; and the route's DPoP proof check asserted
  `htm: "GET"` whatever the method was, so a conforming proof on a `POST /userinfo` was refused as an
  `htm` mismatch — an existing defect nothing had exercised.

- conformance: two findings from the OpenID Foundation suite runs. The `form_post` delivery page
  submits itself with a classic script placed after the form rather than a module script in `<head>`,
  so a user agent that runs scripts but not ES modules — some embedded webviews, and the suite's own
  scripted browser — is no longer left on a page with no way forward at all; the module-capable and
  scripting-disabled paths are unchanged. And a pushed authorization request refused for an
  unregistered `redirect_uri` now answers `invalid_request`, or `invalid_request_object` where the
  value arrived inside a request object, instead of `invalid_redirect_uri` — a dynamic-registration
  code (RFC 7591) that has no definition in a PAR response, where RFC 9126 §2.3 prints the former.
  The authorization endpoint and dynamic registration are untouched. A third item reported alongside
  them — that client assertion audiences are accepted too widely — was investigated and is not a
  defect: RFC 9126 §2 requires a non-FAPI deployment to accept its issuer identifier, token endpoint
  URL and PAR endpoint URL alike, and the narrow FAPI 2.0 rule was already implemented and is now
  covered for all three audience shapes. `CONFORMANCE.md` records the correction and names
  `fapi.enabled` among the settings a FAPI conformance target needs.

## [0.2.0] - 2026-09-08

Two things define this release. The server is now an authorization server **for** third-party MCP
servers rather than only for its own administrative plane, and SECURITY.md has evidence behind it: a
written threat model, a scanning pipeline, and a container image that is signed and ships an SBOM and
build provenance. A plain OAuth 2.1 client can also discover a deployment at last, through RFC 8414
metadata.

### Added

- mcp: the server is now an authorization server **for** MCP servers, not only for its own admin
  plane. An administrator declares a third-party MCP server as a protected resource of a project — its
  canonical identifier, the scopes it recognises, how its tokens are verified, their lifetime — and the
  token endpoint mints audience-bound tokens for it with no source change and no restart; previously
  every audience but `${ISSUER}/mcp` was refused, so protecting one meant writing an addon override.
  A client with no prior relationship gets its project from the declared resource the request names,
  which is what lets it sign in the right deployment's end-users. Client ID Metadata Documents are
  supported as the mechanism the current MCP authorization revision names first: a `client_id` that is
  an https URL resolves by retrieval and validation and creates no client record
  (`clientIdMetadataDocument.enabled`, off by default). The administrative plane admits document
  identifiers through a super-admin allowlist read live, so a withdrawal takes effect on the agent's
  next call; a dynamically registered client can never administer the instance. A new guide,
  [Protect your MCP server with OAuth](https://foxauth.dev/docs/get-started/protect-your-mcp-server/),
  walks it end to end, and the README's compatibility note is replaced by which identity works where.
- security: published evidence behind SECURITY.md, which until now was a policy with nothing standing
  behind it. A written [threat model](https://foxauth.dev/docs/security/threat-model/) names the
  assets, trust boundaries and attackers (RFC 9700 §3) and, for each threat, the control in the code
  and the test that holds it — including the limitations that are true today (secrets unencrypted at
  rest, CSRF resting on `SameSite=Strict`, the image running as root), because a threat model that
  lists only the good news is not one to plan around. A `Security` workflow runs CodeQL (TypeScript
  and the workflows themselves), `bun audit` on both lockfiles failing on high, dependency review on
  pull requests and a Trivy scan of the built image, on every push and weekly; a `Scorecard` workflow
  publishes an OpenSSF Scorecard; a Dependabot configuration keeps the lockfiles and actions current.
  An [assurance page](https://foxauth.dev/docs/security/assurance/) says where each result is read
  and states plainly what does not exist: no external audit, no paid bounty, no OpenID Foundation
  certification. SECURITY.md gained the same section and the README the badges.

- security: the published container image is now **signed, and ships an SBOM and build provenance**.
  `release.yml` signs it with `cosign` over the digest — keyless, so verification names this
  repository, workflow and tag instead of a key we ask you to trust — and BuildKit attaches an SBOM
  and a `mode=max` provenance document to the pushed index that the signature covers; a signed SLSA
  v1 statement also goes to a transparency log for `gh attestation verify` and admission
  controllers. The release verifies its own signature before finishing, so an unverifiable one fails
  the release rather than reaching an operator. The SBOM matters here because the `Dockerfile` runs
  `apk upgrade`, which makes the package set unrecoverable from the repository. Release assets stay
  unsigned on purpose: documentation, not something anyone executes. Verification commands are on
  the [assurance page](https://foxauth.dev/docs/security/assurance/).

- protocol: authorization server metadata at `GET /.well-known/oauth-authorization-server`
  ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414), spec 038, issue #30). A plain OAuth 2.1
  client that is not an OpenID Connect relying party looks for this path and no other, so until now
  it could not discover a deployment at all — the endpoint URLs had to be configured by hand, one
  path away from where the server was already publishing them. Served unconditionally, readable from
  any origin and in the public rate class, for the reason the OIDC document is: metadata a client
  cannot read is metadata it cannot use.

  The document is pruned rather than a copy. Both documents come from one builder, so they cannot
  disagree on a shared member, but the OAuth one drops the fourteen members whose subject matter is
  OpenID Connect — the userinfo endpoint and its algorithms, ID token algorithms, subject types, ACR
  values, the claims members, RP-initiated logout and back-channel logout. Membership is decided by
  the registering specification, never by presence in the IANA registry: RFC 8414 invites other
  specifications into that registry and OIDC Discovery accepted, so all 51 members are registered
  there and the obvious check would have admitted the exact document the pruning exists to avoid.
  Twelve members an OpenID specification registered are kept anyway, because an OAuth-registered
  member is unreadable without them — request-object algorithms beside RFC 9101's
  `require_signed_request_object`, the CIBA endpoint beside the CIBA grant in
  `grant_types_supported`, the JARM algorithms beside the `jwt` response modes. Each records that
  anchor as data, and a guard fails naming the member if the anchor is removed or reclassified, so
  the justification cannot outlive what it depends on.

- site: the SEO guardrail now checks that structured data is _present_, not only that it is correct
  (spec 037). It could tell whether a description was well-formed and truthful but not that one
  should exist, which is how the comparison pages shipped with no article markup past twenty passing
  rules. `STRUCTURED_COVERAGE` says what each kind of page must carry, an unclassified route fails
  the build naming the file to edit, and both were shown failing before being trusted.

  Around that: the comparison pages went from one inbound link each to twelve, anchored on the
  competitor's name and derived from the collection so a new one appears everywhere on arrival; the
  pricing and comparison pages publish their questions and answers as structured data from the same
  array the page renders, so the two cannot drift and the existing overclaim rule proves it; the
  documentation index grew from 30 words to a real orientation page and the comparison index gained
  a prose summary; and `llms.txt`, generated in the previous release and pointed at by nothing, is
  now named in `robots.txt` and linked from the footer. Claims about other products are reported as
  due for review after 180 days, in the build log and on the page itself — without failing a build,
  because staleness is the passage of time rather than a mistake to block on. Three comparisons
  were added — Ory Hydra, Zitadel and authentik — each researched against that product's own
  documentation, recording a capability their documentation does not describe as not documented
  rather than as absent.

- site: search and AI discoverability, enforced by the build (spec 036). Every page now carries a
  checked title and summary, a per-page `lastmod` from git, structured data and its own social card —
  documentation pages included, which had none of it because Starlight builds its own head. For
  assistants, `/llms.txt` lists every page where it listed none, `/llms-full.txt` covers the
  marketing and comparison pages it previously omitted, each page is available as Markdown at its
  address plus `.md`, and `robots.txt` names ten AI crawlers with the source and date each was
  checked against. Screenshots are declared in an image sitemap.

  Indexing is now one decision in `website/src/data/seo.ts` — the styleguide used to be excluded by a
  `noindex` in one file and an unrelated string match in another — and twenty rules check the shipped
  HTML, failing the build with the page and the rule. Two defects it caught on its first run are
  fixed: the licence page had two top-level headings, and the settings reference skipped a level.

### Fixed

- pkce: a `code_verifier` containing `.` or `~` is accepted. RFC 7636 §4.1 defines the verifier over
  RFC 3986's `unreserved` set, which includes both; the pattern here was base64url, the alphabet the
  _challenge_ is encoded in and the one this project happens to generate verifiers with. A client
  whose verifier used the full range was refused at schema validation before the grant ran, so its
  code could not be redeemed by any verifier — and since PKCE is mandatory here, that client could
  not use the authorization code grant at all. This is the second correction to the same pattern
  after its length, and both survived for the same reason: nothing this server or its suite produces
  is outside base64url, so it could never trip over itself.

- userinfo: a request carrying no credentials is answered the way a protected resource must answer
  one — `401` with a `WWW-Authenticate` challenge, and no error information at all. It was being
  treated as an ordinary schema refusal, so the caller got a status RFC 6750 does not use and no
  challenge to act on; the challenge advertises `DPoP` alongside `Bearer` only when DPoP is switched
  on. A credential that is present and unusable is unchanged: that one is refused with `invalid_token`
  and keeps its error body.

- protocol: a request the schema refuses now answers `400`, not the framework validator's `422`. The
  body was already correct (`invalid_request` with a description); only the status was the
  framework's rather than the protocol's, and RFC 6749 §5.2 defines it as `400`. Scoped to the OAuth
  endpoints: the admin API and `/mcp` keep `422`, where distinguishing a well-formed request with an
  invalid body is what the console and the agent act on.

- protocol: a request parameter the server does not define no longer refuses the request. Ignoring
  one is a `MUST` in RFC 6749 §3.1 **and** §3.2, RFC 8628 §3.1 and CIBA §7.1, and RFC 9126 §2.1
  inherits it for PAR — so `/auth`, `/par`, `/device/auth`, `/backchannel` and `/token` all answer a
  request carrying an extension parameter exactly as they answer one without it, and a Request Object
  may carry extension claims as RFC 9101 §4 permits. The undeclared keys are dropped before
  validation rather than carried, so nothing a client invents is persisted in a pushed request object
  or an interaction record. Because absence from a schema now means "ignore", parameters this server
  must _reject_ are declared explicitly instead: `request_uri` at the pushed endpoint, `request` and
  `request_uri` inside a Request Object, and `authorization_details` at the token endpoint, where
  silently ignoring a client's attempt to narrow its grant would return a broader token than it asked
  for. Elysia's own `normalize` was measured as the alternative and rejected: it also cleans request
  headers, which strips the client certificate and breaks certificate-bound tokens.

- par: a successful push answered with a JSON body and no `Content-Type`, which goes out as
  `application/octet-stream`, and with status 200 rather than the 201 [RFC
  9126](https://datatracker.ietf.org/doc/html/rfc9126) §2.2 requires — a client that checks the media
  type before parsing, as a FAPI client must, got nothing usable out of the `request_uri`. Only the
  success path was affected; refusals were already correct. The handler now returns the object and
  lets the declared response schema serialize it, which also puts that schema to work for the first
  time: it was bypassed by the hand-built response, and the `status: 201` beside it was never a hook
  Elysia reads.

- test: a request to an origin no spec registered used to reach the real network; it is now refused by
  name, with interception installed for every spec so the runner's file order stops deciding it. A
  per-case bound also means a wedged case names itself in twenty seconds instead of idling in silence.

- security: three latent injection sinks closed, none of them reachable today, which is the only
  reason this is a hardening note and not an advisory. The `WWW-Authenticate` challenge escaped the
  quote in a parameter value and left the backslash alone — the one combination that fails, because a
  value ending in a backslash then escaped the _closing_ quote instead: the quoted string ran on and
  everything after it parsed as further auth-params. Values are now stripped rather than escaped,
  which is what [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750) §3 asks for (NQCHAR holds
  neither character), and nothing dynamic reaches a 401 description today only by accident. The
  rendered error page and the device pages interpolated their document title raw, where the plain
  interaction pages already escaped the same position; there is now one escaper in `lib/html/escape.ts`
  with all four callers on it, rather than one file getting it right and its neighbours not.

  The reason the title mattered more than an unreachable sink usually does: the content security
  policy is derived _from_ the finished document, so an injected inline script would have been hashed
  and then authorized by the very header meant to stop it. That chain is now pinned by a test that was
  watched failing — it emitted a `sha256-` for `alert(1)` — rather than left as an argument.

  Separately, every tag and attribute matcher in the policy derivation now reads a document by the
  grammar a browser uses rather than a stricter one. Three spellings of that mistake were found, and
  each of the last two only after the previous was fixed: a tag name is case-insensitive, so `<SCRIPT>`
  was a different tag to the deriver than to the parser; and an end tag may carry both whitespace and
  attributes, so `</script >` and `</script foo="bar">` ended a script everywhere except here. All
  three failed the same way — the block went unrecognized, its hash was never issued, the browser
  blocked a script the page still believed it served, and the page rendered perfectly with the
  capability silently gone. None is a hole; all are the kind of wrong that reports itself nowhere.

  The end-tag pattern is now taken from the corpus the analyser itself checks a regex against rather
  than reasoned about one spelling at a time, which is what produced two of the three rounds. It
  deliberately does not accept `</scriptfoo>` — a tag named `scriptfoo` — since reading that as a close
  would hash the wrong span rather than none.

- test: the invariants behind the escaping and the policy derivation are now checked against generated
  input rather than examples (`test/properties/invariants.spec.ts`, `fast-check` as a dev dependency).
  Both had just cost three rounds each of the same shape: a fix was written for the one spelling that
  had been reported, the suite went green, and the next spelling arrived on the next scan. An example
  answers "does it handle this?"; these state what is true of every input — a challenge carries no
  character that could end a parameter early, every inline script a document serves is authorized by
  the policy derived from it whatever the tags are spelled, `</scriptfoo>` is never read as a close, the
  escaper leaves nothing that could escape its position, and a base32 secret survives being retyped in
  a different case with spaces in it.

  Each property was checked by reintroducing the bug it exists to catch, which is the only way to know
  a property has teeth — and the first draft did not. It passed against the restored escaping bug,
  because a full-Unicode generator has no reason to favour one ASCII character and that invariant is
  about exactly two of them; five hundred runs produced no `"` at all. Generating from the characters
  that actually break the function fails it on the fifth case and shrinks the counterexample to a
  single quotation mark. The lesson is in the file, next to the generator.

- build: the container image no longer ships known-vulnerable OpenSSL, and the base it inherits is now
  a reference rather than a moving target. One package accounted for twenty of the twenty-five open
  scanner alerts — `libssl3`/`libcrypto3` 3.5.7-r0, two high, six medium, twelve low — and the standing
  plan of waiting for the base image to be rebuilt turned out not to work: measured on a fresh pull,
  `oven/bun:alpine` still carried 3.5.7-r0 while Alpine's v3.22 repository already served the fixed
  3.5.8-r0, so cutting a release would have rebuilt from the same vulnerable layer.

  `FROM` is now pinned by digest, and to a versioned tag rather than the floating `alpine`, because
  that is the only form anything keeps current: Dependabot moves a digest when the tag's version
  changes and has no mechanism for "same tag, newer digest"
  ([dependabot-core#1971](https://github.com/dependabot/dependabot-core/issues/1971)), so
  `alpine@sha256:...` would have frozen the image at the day it was written — which is exactly why it
  had been left unpinned. A `docker` entry in the Dependabot configuration keeps the pin moving, and
  `apk upgrade --no-cache` takes the distribution's patches at build time rather than inheriting the
  unpatched half of the digest. Reproducibility over time is the deliberate cost; within a run the
  scan and the release still build identically, and `bun.lock` still pins the application's own
  dependencies. Verified with the Security workflow's own Trivy flags: zero fixable findings at every
  severity, down from twenty.

- ci: the release workflow no longer grants every job write access. `contents: write` and
  `packages: write` sat at the top level, so the test job — which runs whatever a version tag points
  at — held a token that could push to the repository and publish to the registry, for no reason
  beyond the two jobs beside it needing one each. Read at the top, write only where a write happens,
  the shape the security workflow already used. CodeQL also stops scanning `test/`: thirteen of twenty
  high-severity alerts were test assertions — a `redirect_uri` written as a regex with an unescaped
  dot, a `<script>` string a CSP test looks for, a password hashed by a fixture — ranked beside two
  real findings in `lib/` that nobody could see for the noise. An alert list is a queue, and a queue
  that is two-thirds false is not read.

- ci: a commit that touches only the console's React components no longer fails the coverage gate.
  Those components are pulled into the coverage run by the shell's module graph but never rendered by
  it, so they report between 1% and 10%, and their 5,923 lines drag the project number from 97% to
  82% — which Codecov then holds every other commit to. One duly failed at 63% of a diff that was a
  single `.tsx` file. A `codecov.yml` ignores the browser bundle and changes no target, because every
  commit scored on server code has hit 100% of its diff; the two modules beside those components that
  `bun test` does exercise stay measured. They are verified where they run, by the Playwright capture
  in the site build.

- test: the login throttle specs no longer sit one second away from bun's 5s default timeout. Each
  spends the failure cap and each attempt costs an argon2 verification, so the file runs at roughly 3s
  per test and contention from the rest of the suite decides the rest — which it did once, and a
  timeout is reported as a failing assertion, reading like a broken throttle rather than a slow one.
  The budget is stated once at the top of the file.

- site: the home page no longer scrolls sideways on a phone. Below the `lg` breakpoint the hero grid
  declared no base column count, so it formed a single implicit `auto` track sized to its content —
  the page laid out 839px wide inside a 375px viewport, with the headline running off-screen. A grid
  track's automatic minimum is `min-content`, so one unbreakable string sets the width of the whole
  page; `overflow-x-auto` on the element does not save it, because by then the ancestor track has
  already grown. Every grid now carries an explicit `grid-cols-1`, the settings reference uses
  `minmax(0,1fr)` rather than `1fr` for the same reason, and long identifiers in prose break instead
  of widening the page. Three pages were affected, the settings reference and the changelog beside
  the home page; all thirteen now measure no overflow at fourteen widths from 320px up, with the
  desktop layout unchanged.

### Security

- ci: every GitHub Action is pinned to a full commit SHA with the version beside it in a comment,
  where all twenty were previously mutable tags and one — the Fly deployment's `setup-flyctl` — was
  the `master` branch. A tag is a pointer its owner can move, so the workflows granted whatever
  those repositories held at the moment a job started, including the ones holding the registry
  credential and the release token. This is the OpenSSF Scorecard `Pinned-Dependencies` check, which
  scored 0 against the badge the README publishes, and the gap was invisible in review precisely
  because a version tag reads like a version. Dependabot updates a pinned SHA and its comment
  together, so the pins stay current rather than merely frozen.

  Landed with the five action upgrades this made necessary to resolve — `checkout` to v7.0.1,
  `upload-artifact` to v7.0.1, `upload-pages-artifact` to v5.0.0, `metadata-action` to v6.2.0 and
  `action-gh-release` to v3.0.3. `upload-pages-artifact` stops including dotfiles as of v4, which the
  site build does not emit; `deploy-pages` stays on v4, which that version still requires.

## [0.1.0] - 2026-09-03

The first tagged release: everything the server accumulated before a version number existed.

### Added

- Reported faults now name where in the server they happened (spec 035). An operator paged about a
  failure could see which endpoint broke but not which line broke it, and had to open the internal
  console and look the reference up to find out — while every fault on one endpoint arrived under a
  byte-identical title, so a list of alerts could not be scanned at all. A reported fault now carries
  the code location the internal record already held, is titled with the diagnostic message rather
  than a synthetic endpoint string, and is located by a second line built from the method, the route
  pattern and that code location. The file is also a searchable tag, so an operator can ask what is
  failing in one part of the server rather than only inspecting one fault at a time. Grouping is
  untouched: the store's own key is still the only thing the destination groups on, and it already
  incorporated the code location. Nothing else was widened — the location joined the explicit list of
  permitted outbound fields, which is now enforced one level deeper so a value added inside it later
  cannot ship unnoticed, and a raw stack, an error object, or a frame still carrying the failure
  message remain unsendable.
- Optional Sentry reporting for recorded faults (spec 034). The error store already kept a durable
  record of every unexpected internal fault, but nothing told anyone one had happened — an operator
  learned about a failure by going to look for it. With `sentry.enabled` on and an ingestion
  credential configured, each fault the store records is also reported to the operator's own Sentry
  project, carrying the endpoint, the kind of failure, the client it is attributable to and the same
  `error_reference` the caller received, so an alert leads straight back to the full internal record.
  The environment and release labels are read from what the deployment already declares — `NODE_ENV`
  and the `package.json` version — rather than typed into the console, because a label maintained by
  hand is stale from the next deploy onwards, and a stale release label sends an investigation to a
  build that never ran. No new environment variable was introduced for it; the console shows the
  resolved values read-only instead.

  Off by default, one instance-wide destination, super-admin only, and it requires the error store:
  the outbound event is projected _from_ the internal record, so reporting is an additional
  destination and never an alternative to recording. The ingestion credential is write-only through
  the admin surface — a read reports only whether one is stored, and the audit trail records that it
  changed without recording its value.

  The **official `@sentry/elysia` plugin is deliberately not used**, and that is the substance of the
  work. Reading its source (v10.73.0) showed three disqualifying behaviours: its capture predicate
  reads the response status and reports when it is still `undefined`, so routine `invalid_grant` /
  `invalid_client` rejections — the normal traffic of a token endpoint — would ship as unhandled
  faults; it attaches the full request URL and headers unconditionally, which on `/authorize` means
  `state`, `code_challenge`, `id_token_hint`, `login_hint`, `request_uri` and on an error redirect
  `code`, plus `Authorization` and `DPoP`; and it writes `sentry-trace`/`baggage` onto every response
  while opening spans across all nine Elysia lifecycle phases. Instead `@sentry/bun` is used directly
  with `defaultIntegrations: false` and no integrations, as an envelope-and-transport layer only.
  `lib/sentry/` registers no Elysia hook at all, so there is no code on the request path to add a
  header, add latency, or fail; the event is assembled from a named list of permitted fields
  (excluding `actor` and `userAgent`) rather than by scrubbing a captured request, and dispatch
  happens from exactly one place — inside `captureFault`'s record continuation, which runs only after
  the fault is classified and locally recorded. Outbound volume is bounded by `sentry.queueDepth`
  with counted drops, so an error storm cannot amplify into the monitoring channel. The default test
  run performs no outbound delivery yet can inspect exactly what would have been sent, which is what
  makes the data-protection guarantees assertions rather than review opinions.
  `wiki/concepts/sentry-plugin-not-used.md` records the reasoning; `test/sentry/` holds it.

- Brute-force protection on the password sign-in door (issue #9, spec 032). `POST /ui/:uid/login`
  accepted unlimited guesses against any address, each one buying a full password hash on a
  shared-CPU machine — so the door was both a credential-stuffing opportunity and a cheap
  CPU-exhaustion vector, and the only unbounded secret surface left in the server. Failed attempts
  are now counted per `${bucketId}:${email}` in a new `LoginThrottle` area; at the cap the door shuts
  for that address and refuses everything — **including the correct password** — until the window
  ends, and each further exhaustion shuts it for longer, doubling 15 → 30 → 60 minutes. That holds a
  sustained attack to roughly 120 guesses a day against unlimited before, and a refused attempt does
  no lookup and no hashing, so the CPU half of the issue closes with the guessing half.
  The refusal is the door's existing invalid-credentials page, produced by the _same expression_ the
  two ordinary failure paths use rather than a copy of the wording, and failures are counted for
  addresses that resolve to no account — so neither the response nor the existence of a counter is
  evidence that an address is registered. Two things clear a counter, and both are proofs an attacker
  guessing passwords does not hold: a password that verifies, and a **completed** password reset.
  The second is why no "enter the code from your email" step was built — consuming the emailed secret
  already proves control of the address, through a flow that has its own cooldown and cap, while a
  dedicated step would have been an account-existence oracle, an email-bombing vector, a hard mail
  dependency for sign-in, and unavailable to the one bucket with no reset at all. Requesting a reset
  clears nothing.
  Three decisions are worth reading the code for. The record's retention (24h from the last failure)
  must **outlive** its own lockout window or the escalation silently never happens — a counter reaped
  when the door reopens restores the opening allowance, so an attacker who waits is never escalated;
  the boot validator enforces the ordering. The escalation ceiling is the first window wherever the
  bucket sets `totpRequired`, read from the bucket's policy and never from its identity, because a
  guessed password is not a sign-in there while the lockout it risks — the admin console, which has no
  self-service reset — is the one nobody can undo. And the counter's key is built by one new
  `emailScopedId` helper stating its rule as parity with `findByEmail`'s normalization: a key built
  from the raw submission would have given a 16-letter address 65,536 independent counters, and every
  test written in lower case would still have passed. That helper replaced three copies of the
  expression and one inlined fourth in the end-user delete route which had dropped its `toLowerCase()`
  — under the in-memory adapter, whose user store does not normalise what it stores, that line was
  already missing the email-scoped records of mixed-case accounts and reporting success.
  Bounds are `loginThrottle.failureCap`, `.windowSeconds` and `.windowCeilingSeconds`, super-admin
  editable and boot-only. There is deliberately no `loginThrottle.enabled`: unlike the per-origin
  limiter this is persisted, holds across restarts and machines, and is therefore a security boundary
  rather than a resource protection — a kill switch for it is a switch that reopens the vulnerability,
  so the validator bounds the numbers to a range in which the protection still means something instead.

- The last three security headers issue #2 asked for (issues #10 and #2, spec 029).
  `Strict-Transport-Security: max-age=63072000; includeSubDomains` and a `Permissions-Policy` denying
  seventeen high-privilege browser features now ride on every response, from the same pre-routing hook
  that already carried `nosniff`, `Referrer-Policy` and the non-page content policy — so they reach the
  error pipeline, the named admin instance and static assets, which after-the-fact response hooks miss
  silently. `preload` is deliberately omitted and the reason recorded: the deployment host is already
  preloaded through the whole `dev` TLD, submission needs an apex domain this deployment does not own,
  and the effect is global and slow to undo — a self-hoster's choice to add at their own edge. HSTS is
  emitted unconditionally, including over plaintext, because TLS terminates at the proxy so the hop RFC
  6797 governs is HTTPS, and the alternatives are either spoofable (`X-Forwarded-Proto`) or invisible
  to the merge gate. `clipboard-write` is **not** denied, and a named test enforces that: antd's
  `copyable` reaches for `navigator.clipboard.writeText` first, so denying it would have stranded five
  secret-copy surfaces — the TOTP enrolment secret among them — on the deprecated `execCommand` path.
  The legacy `X-Frame-Options: DENY` is emitted by `htmlResponse` on rendered pages only, derived from
  the same single evaluation as `frame-ancestors` and therefore absent on the one deliberately framable
  page, the `form_post` hand-off; a blanket emission was not merely inelegant but unimplementable,
  since a returned `Response` can override a merged header but never remove one and the header has no
  permissive value, so it would have broken silent authentication with no downstream fix
- Per-origin request rate limiting (issue #1). An origin that spends its allowance inside a window is
  refused with `429` and a `Retry-After`, before the endpoint does any work. Allowances are tiered by
  route class rather than blanket — strict on the unauthenticated and expensive surface, loose on
  static assets and discovery, the liveness probe exempt — declared as a third dimension on the route
  table under the same two-way drift guard as the feature gate and CORS. Counting is per instance and
  never persisted, so no storage area is added; the price is that the effective allowance multiplies
  by concurrent machine count and clears on restart, which is why this is a resource protection and
  not a security boundary. The per-identity throttles are unchanged, and the login door's brute-force
  protection remains issue #9. Nine `rateLimit.*` settings, editable from the console; invalid values
  refuse the boot rather than serving with limiting silently absent. `elysia-rate-limit` was evaluated
  and not adopted: its single static `errorResponse` cannot produce this server's three channel
  shapes, and its default refunds requests whose handler threw — which is every failed credential
  guess
- The administration console can be put behind the second factor. A new settings resource under
  `/admin/api/admins` carries the reserved admin bucket's `totpRequired` — audited as
  `admin.settings.update`, exposed to MCP as `admin_settings_read` and `admin_settings_update`, with
  a switch on the Admins page. The generic bucket routes still refuse that bucket; this is the
  surface their 403 already pointed at. Nobody is locked out by turning it on: an administrator
  without an authenticator enrols at their next sign-in
- TOTP second factor per user bucket: `totpRequired` makes a password sign-in also require a
  six-digit authenticator code, with enrolment at registration and at the first sign-in of an
  existing account, RFC 4226/6238 implemented in-repo against the published test vectors, replay and
  two-tier throttling, `amr: ['pwd','otp']` on the ID token, and operator recovery via
  `DELETE /admin/api/buckets/:id/users/:uid/totp` (audited, ends sessions, exposed to MCP as
  `bucket_user_totp_clear`). Federated sign-in is not gated (spec 027)
- CORS support: preflight handling, open CORS on discovery/JWKS, client-based CORS on the token
  family driven by a per-project `corsOrigins` allow-list, `cors.enabled` setting (spec 011)
- Hardening headers on every response that is not a rendered page — `nosniff`, `no-referrer`, and a
  content policy of `default-src 'none'` plus `frame-ancestors 'none'` — across the protocol
  endpoints, the admin API, MCP and the static surface, including responses built by the error
  pipeline. Rendered pages keep their own derived policy (spec 026)
- Content-Security-Policy on every rendered page, derived per document — `script-src 'none'` on
  script-free pages, hashed inline styles; hydrated pages use precompiled antd CSS under
  `zeroRuntime` (specs 018/032, `74cc208`, `1a4628d`)
- Admin audit trail covers all 23 mutating admin routes and became readable:
  `GET /admin/api/audit` + an Audit page in the console (spec 016)
- Rich Authorization Requests (RFC 9396) work end to end on the code and refresh flows: consent
  display, grant persistence, working hook defaults, per-client `authorizationDetailsTypes` via
  the admin API (spec 015)
- Self-service end-user password reset, bucket-scoped, with throttling (spec 020)
- Upstream OIDC federation per bucket — end users sign in through their own identity provider;
  admin management plane included (spec 022)
- Admin MCP control plane: administer the instance from an AI agent at `POST /mcp`, served as an
  OAuth 2.1 protected resource of the server itself (spec 024)
- Durable server error store an operator can read — internal faults no longer vanish with the
  console (spec 025)
- `bun run db:setup` provisions every collection and index from a declared storage inventory under
  a drift guard, including TTLs for verification areas and unique per-bucket email indexes
  (spec 012)

### Changed

- Groups read as themselves in the admin console, and a personal group is nobody else's to work in.
  Four things were wrong at once, all of them about the same list. Every personal group displayed as
  the bare word "Personal" — including in a super administrator's list, where N administrators
  produced N identical rows and the owner's email that is _stored_ as the group's name was thrown
  away by both display sites. Personal groups appeared in the Groups table at all, which is a page
  about the teams work is shared with. `GET /admin/api/scope` offered a super administrator every
  group on the instance, other people's personal groups among them, and `PUT` accepted them — so the
  console could be pointed at one person's own workspace by somebody who was never in it. And the
  reserved holding group was called "Unassigned", which reads like a data-quality problem rather than
  the name of the one group that is not a tenant.
  It is now: **System** (`SYSTEM_GROUP_NAME`, `$set` by the deployment seed so an existing database is
  renamed too, and preferred over the stored name by the console so it does not wait on `db:setup`);
  no personal rows in the Groups table; and one `groupLabel` helper shared by the table and the scope
  switcher, rendering "Personal" for your own and "Personal — owner@email" for a personal group you
  were added to. Both scope routes now apply the same carve-out — the list never offers what the
  switch would refuse — and all three of the switch's refusals still say one thing, so it cannot be
  used to learn which ids are real or which of them are personal. Whether a personal group is your
  own is answered by the server from `members[0]`, the only place that can answer it: a shared
  personal group may promote a second owner, and `findPersonalFor` matches any personal group you are
  a member of
- Switching the console's active scope no longer writes to the audit trail. `PUT /admin/api/scope`
  changes `AdminSession.activeGroupId` and nothing else, and grants no access a member did not already
  have — while which scope a change was made from is already carried by `ownerGroupId` on that change's
  own entry. It joins `POST /admin/api/logout` in `excludedAdminRoutes`, whose reason already described
  it: session lifecycle, not a change to a managed entity. `scope_switch` is withdrawn from the agent
  surface with it, as `inapplicable` — an agent has no console session, so the tool could only ever
  answer 400
- `README.md` and `AGENTS.md` now describe the server that exists (issue #20, spec 031). The endpoint
  table was wrong on six of eleven rows — `/authorize`, `/introspect`, `/revoke`, `/register`,
  `/session/end` and `/request` are really `/auth`, `/token/introspect`, `/token/revocation`, `/reg`,
  `/logout` and `/par` — and was missing twelve routes and every method on `/userinfo` but `GET`. It is
  now derived from `lib/consts/route_classification.ts`, which pairs each route with its governing flag
  and is already guarded both ways against `elysia.routes`, and it is split by availability because 23
  of the 28 feature flags default off and a disabled endpoint is deliberately indistinguishable from
  one that does not exist. Five Features bullets had presented opt-in capabilities as shipping
  defaults, Client Credentials and Refresh Token among them; the Features list now separates what a
  default install serves from what a deployment switches on, and drops the claim of static client
  registration, which was removed when clients became DB-backed. The Standards table gained eleven
  implemented specifications plus a flag column, and admits CIBA, JARM and OAuth 2.1, which its
  RFC-only shape had excluded. `AGENTS.md` had pointed contributors and agents at `/interaction/*`
  routes; login and consent are served under `/ui/:uid/*`. Two claims the issue asked for were dropped
  after checking the code: RFC 8414 is not implemented, and no `/.well-known/oauth-authorization-server`
  is served
- **BREAKING:** feature flags now gate their endpoints — a disabled feature's routes answer 404
  instead of staying silently live (spec 010)
- **BREAKING:** deletion means what it reads as — projects/buckets refuse deletion while non-empty
  (409 with machine-readable blockers); deleting a client or end-user cascades to their sessions,
  grants and tokens (spec 019)
- **BREAKING:** pairwise `sub` values derive from stored server state instead of `os.hostname()`.
  They change exactly once, on first start of this version, for clients registered
  `subjectType: 'pairwise'` — then never again across restarts and scale-out (spec 023)
- **BREAKING:** `richAuthorizationRequests.types` is now a serializable descriptor map (`label`,
  per-common-field constraints, `allowUnknownFields`) editable in the admin settings; enabling the
  feature with an empty map fails validation. A code-registered `validate` remains an optional
  escape hatch (spec 015)
- **BREAKING:** `allowOmittingSingleRegisteredRedirectUri` moved into the Application
  Configuration (`authorization.allowOmittingSingleRegisteredRedirectUri`) and now defaults to
  **disabled**; enable it in the admin settings and restart to restore the old behavior
- Interaction UI: post-registration "check your inbox" notice renders, registration refusals are
  styled pages, consent permissions carry headings and friendly labels, decorative Google button
  removed (spec 021)

### Removed

- Seven unreferenced modules deleted (issue #19, spec 030): the whole `lib/views/` directory of legacy
  interaction templates — safe because spec 015's `'rar-detail'` consent group had taken over the RAR
  rendering that was its one unique job — plus the `Stub.tsx` admin placeholder, `helpers/params.ts`,
  `helpers/set_www_authenticate.ts` and `helpers/_/pick_by.ts`. The two addon functions the issue
  suspected of being dead are **kept**: `assertClaimsParameter` and
  `assertJwtClientAuthClaimsAndHeader` are live override seams reached through the call-time registry
  in `lib/addon/index.ts`, so an empty body is their default rather than an abandoned stub, and each
  now carries a comment saying so. `AGENTS.md`'s source-tree map lost three stale entries it had kept
  describing — `views/`, the long-deleted `provider.ts`, and CORS under `shared/`. Test counts, type-error
  count and lint findings all held at their pre-change values.

### Fixed

- A super administrator's scope switch is no longer accepted and then silently discarded.
  `resolveActiveGroup` (`lib/admin/auth/rbac.ts`) re-validated the session's choice against membership
  alone, with no exception for the role that is allowed to switch without one — so a super
  administrator switching into a group answered 200, and on the very next request their active scope
  resolved to empty and `assertActiveGroup` sent everything they created to the `unassigned` holding
  group while the console went on showing the group they picked. Their choice is now honoured after
  one re-read of the group, which also refuses it if the group has since been deleted or is an
  administrator's personal group

- An agent naming an operation the MCP surface withholds now hears why, instead of `Tool <name> not
found`. The refusal text existed and never ran: the call that delivered it sat in the tool
  registration loop, where it can only fire for a name that _is_ registered, and an excluded operation
  never is. It now also runs in the transport, before the SDK and after the credential, answering a
  failed tool call rather than a JSON-RPC error. A genuine typo still gets the SDK's not-found, so a
  mistake is not dressed up as a policy decision
- The server could not boot against MongoDB: the DPoP nonce secret came back from the driver as a
  BSON `Binary` and failed its own round-trip check (`71d9b53`)
- PKCE accepts the full RFC 7636 verifier length range (43–128), not only 43 (`6dce3f7`)
- Native clients can complete an interactive sign-in (`ba5629d`)
- Interaction pages can hand off to a foreign callback under the CSP (`271d518`)
- The settings audit records only the fields a save actually changed (`b630c73`)
- Logging out of the admin console actually signs the operator out: it now ends the provider
  session as well as the console's own, and clears both cookies with the `Path` they were set with
  (Elysia's `cookie.remove()` omits `Path`, so the browser defaulted it to the request's directory
  and cleared a different cookie)
- The interaction cookie is cleared at its own path and expires with the interaction: the clear went
  out with `Path=/` while the cookie lives at `/ui/<uid>` (a different cookie, so a browser kept it),
  and its `Max-Age` was set in milliseconds -- a ~41-day lifetime for a one-hour interaction
- Small-batch fixes: duplicate first-run admin setup surface removed, error pages carry the real
  status and illustration, stale `interaction.returnTo` corrected, unimplemented CIBA `push` mode
  removed from the admin schema (spec 018)

### Security

- The reserved admin bucket can no longer be gated on email verification. Both paths that create an
  administrator write `verified: false` and no verification mail is ever sent for that bucket, so the
  flag would have refused every administrator at the door with no way back short of editing the
  database. It was unreachable through the API rather than prevented; it is now refused at the point
  of enforcement
- The end-user cookies (`_session`, `_interaction`) carry `Secure` -- and the `/ui/*` responses,
  which is where the authenticated `_session` is first written, now carry the full
  `HttpOnly; SameSite=Strict; Secure` set instead of no attributes at all: that route family
  declared a second, option-less cookie schema, so a `Set-Cookie` from it inherited nothing.
  Both schemas now build from one `endUserCookieAttributes` owner
- The admin console verifies its id_token's signature (plus `nonce`, expiry, audience) against the
  live keystore before trusting it — previously a documented decode-only shortcut (spec 017)
- The DPoP nonce secret is self-provisioned at startup, making the requireNonce-without-secret 500
  state unrepresentable (spec 014)

[Unreleased]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/RedFox-Soft/OAuth-server.ts/releases/tag/v0.1.0
