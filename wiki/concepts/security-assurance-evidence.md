---
type: concept
title: "Security assurance: what evidence the project publishes, and what it refuses to claim"
tags: [architecture, contract]
sources: [oauth-server-codebase]
created: 2026-09-07
updated: 2026-09-07
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:ci-workflows
      source: oauth-server-codebase
      evidence: ".github/workflows/security.yml — CodeQL (javascript-typescript, actions), bun audit --audit-level=high on both lockfiles, dependency-review on PRs, Trivy image scan uploaded as SARIF; .github/workflows/scorecard.yml — ossf/scorecard-action with publish_results: true"
      confidence: high
      status: current
---

# Security assurance: what evidence the project publishes, and what it refuses to claim

Until 2026-09-07 `SECURITY.md` was a disclosure policy with nothing standing behind it: a contact,
response times, a safe harbour, and no way for a reader to check whether any of the controls the
README lists actually hold. The gap was named in a public-facing review as "policy, no proof". This
page records what was published to close it and, more usefully, the decisions inside that work.

## What exists now

- **A threat model** at `website/src/content/docs/docs/security/threat-model.mdx`, structured after
  RFC 9700 §3 (attackers) and §4 (threats). Every control row names the source file and the spec
  under `test/` that holds it; the page's own maintenance rule is that a control without a test is
  a control that can vanish in a refactor unnoticed. It carries a **Known limitations** section
  that names the real gaps — secrets unencrypted at rest, CSRF resting on `SameSite=Strict`, cookies
  unsigned, verification link tokens unhashed, no per-code device attempt counter, the image
  running as root, TOTP not seeded on for the admin bucket — each with its compensating control.
- **An assurance page** at `docs/security/assurance.mdx`: what each scan covers, what it does on a
  finding, where the result is read, and a section titled "What has not been done" — no external
  audit, no paid bounty, no OpenID Foundation certification, no fuzzing or signed releases.
- **`.github/workflows/security.yml`**: CodeQL over `javascript-typescript` *and* `actions` with the
  `security-extended` suite; `bun audit --audit-level=high` on both lockfiles (server and
  `website/`), which fails the run; `actions/dependency-review-action` on pull requests; a Trivy scan
  of the image built from the real `Dockerfile`, uploaded to code scanning under category
  `trivy-image`. Triggers: push to `main`, pull requests, weekly cron, manual.
- **`.github/workflows/scorecard.yml`** publishing an OpenSSF Scorecard, and
  **`.github/dependabot.yml`** for the `bun` ecosystem in `/` and `/website` plus `github-actions`.
- `SECURITY.md` gained an **Assurance** section (rendered at `/security/` by the site), the README the
  two badges and a Security section, `CHANGELOG.md` the entry.

## Decisions worth keeping

**The limitations are the evidence.** A threat model that lists only controls reads as marketing;
the list of what is *not* defended, with the compensating control for each, is what lets an
operator plan. The same rule governs the assurance page: an item leaves "What has not been done"
only by moving to a section above with a link, never by deletion.

**The image scan does not fail the build.** A red build nobody can turn green teaches people to ignore
red builds, so the finding is published to code scanning instead, with `ignore-unfixed: true` because
an unfixable finding gives a reader nothing to do. `bun audit`, by contrast, *does* fail: a lockfile
bump is always within the repository's power.

**Superseded 2026-09-08 — the base image was within its power after all.** This page used to say the
remedy for a Trivy finding was "a rebuild once upstream ships a fix — not a change in this repository",
and the release-then-wait reading of that was measured wrong: on a fresh pull `oven/bun:alpine` carried
`libssl3 3.5.7-r0` while Alpine's v3.22 repository already served the fixed `3.5.8-r0`, so cutting a
release rebuilt from the same vulnerable base. One OpenSSL package accounted for twenty of twenty-five
open alerts. The Dockerfile now pins the base by digest on a *versioned* tag — the floating `alpine`
could not be pinned, because Dependabot moves a digest only when the tag version changes
(dependabot-core#1971) — and follows it with `apk upgrade --no-cache`. Verified locally with the
workflow's own Trivy flags: zero fixable findings at every severity. The scan still does not fail the
build; what changed is that its findings are now actionable here, which is the argument this paragraph
originally got backwards.

**Two audits, not one.** `website/` is an independent Bun project with its own lockfile and a build
that runs a browser; it is not exempt because it is "just the site". On 2026-09-07 the root lockfile
carried one high advisory (picomatch 4.0.3, a dev-only transitive of typescript-eslint); `bun audit
fix` moved it to 4.0.4 so the new gate was green from its first run.

**Actions are referenced by major tag, not SHA.** Consistent with the four existing workflows.
Scorecard's `Pinned-Dependencies` check will score this down, and that is accepted for now: the
assurance page says a low score is information, and switching all six workflows to SHA pins (which
Dependabot's `github-actions` entry would then maintain) is a single later decision, not something
to do in one file and not the others.

**Scorecard's workflow shape is constrained.** It publishes only when the job runs on the default
branch with `permissions: read-all`, `persist-credentials: false` on checkout, and no steps other
than the action, an artifact upload and a SARIF upload. The file says so in its header because the
failure mode is silent: the run goes green and nothing is published.

**No tests for any of this**, by the owner's standing decision of 2026-09-03 that the site has no
test suite and `test/repo/*` does not come back: the site's verification is `astro check` plus the build's twenty-two SEO rules,
which the two new pages pass (unique titles inside the 15–60 band, descriptions inside 70–160,
reachable from `/docs/` and the Starlight sidebar, `TechArticle` from `StarlightHead.astro`).

## Related

- [[per-origin-rate-limiting]] and [[login-door-throttle]] — the two pages the threat model leans on
  for the "resource protection versus security boundary" distinction.
- [[html-response-security-policy]], [[non-html-response-hardening]], [[end-user-cookie-attributes]] —
  the browser-surface rows.
- [[admin-mcp-control-plane]], [[admin-audit-trail]] — the administration rows.
- [[sentry-plugin-not-used]] — why the telemetry row can say events are refused rather than scrubbed.
