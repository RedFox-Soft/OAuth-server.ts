---
type: concept
title: 'The settings console is read from one descriptor'
tags: [architecture, config, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-03
updated: 2026-09-03
graph:
  node_type: concept
  relationships:
    - predicate: constrained_by
      object: concept:feature-flag-gating
      source: oauth-server-codebase
      evidence: "A key absent from the catalog is not editable, and the absence is recorded where the descriptor would be — lib/admin/settings/catalog.ts:207: 'dpop.allowReplay is deliberately absent, and this is the record of why.'"
      confidence: high
      status: current
    - predicate: constrained_by
      object: concept:rich-authorization-requests
      source: oauth-server-codebase
      evidence: "The types editor enumerates the five fields RFC 9396 defines and offers permitted values only for the four list-valued ones, so the two shapes that used to produce a 422 are unexpressible rather than merely checked; the draft it calls clean is pinned by test to one validateConfiguration accepts."
      confidence: high
      status: current
---

# The settings console is read from one descriptor

The admin settings page holds **no second list of settings**. Which pane a setting appears on, the
line beside its control, the suffix on its number and whether changing it is a security decision are
all fields on the descriptor in `lib/admin/settings/catalog.ts`, served from the catalog rather than
compiled into the browser bundle.

That is the load-bearing part, and the reason is specific: a second copy in the browser could name a
pane the catalog never fills, or miss one it does, **with nothing to catch either**.
`lib/admin/settings/catalog.ts:19` states the invariant the tests hold — "every declared domain
holds at least one setting and every setting names a declared domain".

## What the descriptor carries, and why each field exists

- `domain` files each setting onto one of six panes (`grants`, `request-security`, `endpoints`,
  `signin-abuse`, `diagnostics`, `integrations`). Before it, sixty-odd settings sat on one
  unsectioned scroll and the `group` each descriptor already carried was discarded at render for
  fourteen of them.
- `summary` is one line, **bounded at 100 characters and pinned by test**
  (`lib/admin/settings/catalog.ts:83`). The bound is what stops summary and `description` collapsing
  back into one wall of text — several descriptions run past a hundred words, so the prose used to be
  most of the page height.
- `unit` puts a suffix on every number, because fourteen of them read as bare integers and "900" gave
  no clue whether it meant seconds, days or requests. The invariant is about *presence*, not spelling
  (`catalog.ts:96`).
- `risk: 'security'` marks the six settings whose change has a security consequence in some
  direction, which used to look identical to a user-code mask. Saving one is a confirmed action
  listing each change as old → new.

`hasDetail` is **not** a descriptor field — it is a derivation
(`lib/admin/ui/settings/model.ts:72`). Seventeen descriptions turn out to be shorter than the
summary written for them ("Requires mTLS enabled."), so it renders no disclosure for those rather
than one that opens onto less than the line above it.

## The demotion criterion, and the audit that applied it

The question that decides whether a setting belongs in the catalog at all is recorded in
`lib/sentry/dispatch.ts:31`, next to the code it was first argued about rather than in a document:

> Nor is there a question an operator could answer to set it. Choosing a value needs the fault rate
> measured against the destination's ingest latency, which nobody has — so the setting would sit at
> its default forever, and a setting that does nothing is worse than its absence.

Every catalogued setting (sixty-two at the time) was audited against it. **One** failed:
`dpop.allowReplay`, which skips the uniqueness check on a proof's `jti` entirely
(`lib/helpers/validate_dpop.ts`), so an intercepted token becomes replayable while discovery goes on
advertising DPoP. Every direction of it removes a check, so there is no operator question behind it;
its two real callers — a conformance suite and someone repeating a request while diagnosing —
configure it at startup.

Two things about that demotion are easy to get wrong:

1. **The key stays in `ApplicationConfig`** and `validate_dpop.ts` reads it unchanged. What leaving
   the catalog removes is the console *and the MCP surface*, because the admin `PUT` filters
   submissions against this catalog. Same technique as `dpop.nonceSecret` and `sentry.dsn`.
2. **The reason is written where the descriptor used to be** (`catalog.ts:207`), so the next reader
   finds an argument instead of a gap.

Nothing else was demotable, and two near-misses are worth recording because they look demotable and
are not. The nine `rateLimit.*` keys are pinned by FR-020, whose test exists precisely to prevent it.
And `loginThrottle.windowCeilingSeconds` looked like the throttle trio's leftover until the curve was
read: `windowFor` doubles the window and clamps at the ceiling, so **from the third lockout onward
only the ceiling is in force**, and it alone sets the settled rate of a sustained attack. The Login
throttle card now states that rate live — "about 120 password guesses a day" — cross-checked in test
against the real `windowFor` rather than restating its formula.

## Three save models became one, and the two that stayed say why

The page had a header diff-save for catalogued settings plus SMTP's and Sentry's own buttons, with
nothing to say which covered what. One save bar now replaces the header button: a count, a standing
note that these apply **at restart**, a review drawer showing each pending change as old → new, and
discard.

Restart was the most important fact on the page and was only ever reported *after* a save — the one
moment it cannot be acted on. SMTP and Sentry keep their own buttons because they are separate
endpoints, and now say "applies immediately" so the distinction between the boot-only
`ApplicationConfig` surface and the runtime stores is visible rather than folklore.

Gating booleans sit in a card header with their dependents inside, **disabled rather than hidden**.
Hiding them meant an operator could not see what enabling a feature would let them configure, and
let a dirty value vanish from the page while still being part of the next submission.

## Why the derivations live in a React-free module

`lib/admin/ui/settings/model.ts` holds the logic that can be *wrong* — which pane a setting lands on,
which rows a search matches, which keys count as edited, what a primary toggle resets on the way
down. It is not there for tidiness: **none of it is reachable by a test while it sits inside a
component, because this repo has no DOM test harness** (`model.ts:1-8`).

The module **mirrors** `catalog.ts` rather than importing it, and the comment at `model.ts:10` gives
the trade: the catalog imports `ApplicationConfig`, which reaches the whole configuration layer, and
pulling that into the browser bundle to borrow an interface is a poor deal. Two type-level
assignments in `test/admin/ui_settings_model.spec.ts` fail typecheck if the mirror drifts — which is
the failure the old per-component copy invited.

Bespoke controls are a **registry keyed by setting** (`lib/admin/ui/settings/controls.tsx:103`)
rather than a branch inside `Control`, which exists to know nothing about individual settings.

## A structured editor restates server rules, so it is pinned to them

The RAR types editor and the user-code mask control both encode rules that live in
`validateConfiguration` — exactly what this repo's comments warn against. The discipline that makes
it safe is the direction of the test: **a draft the editor calls clean must be one
`validateConfiguration` accepts.** A form showing no complaint and then a 422 on save is worse than
the raw textarea it replaced, which at least never claimed to know.

Writing that test found an asymmetry rather than confirming a symmetry. The server's rule is
`label.length`, so a label of only spaces satisfies it and the consent screen then shows a blank
where the name of the thing being authorized should be. The editor stays stricter, and the difference
is enumerated in a test of its own so a later reader does not "fix" it in either direction by
accident. Whether the validator should refuse a blank-looking label is a question about server
behaviour, deliberately left open.

Two further consequences of asking for the decision instead of the encoding:

- A duplicate identifier is now caught. The JSON object **silently collapsed** it: two entries with
  the same key were one type, and nothing said which survived.
- Edits land in the page's values immediately rather than on closing the drawer, so the save bar
  counts them like any other pending change. A structured editor keeping its own draft would be a
  second place where unsaved state lives.

## What is not verified

The page's rendered layout has not been checked in a browser. The logic is covered by
`test/admin/ui_settings_model.spec.ts`, `settings_metadata.spec.ts` and `settings_catalog.spec.ts`;
the visual result is not.

## Related

- [[feature-flag-gating]] — the flags this page edits, and why a key's absence from the catalog
  removes it from the agent surface too.
- [[user-code-mask-entropy]] — the other rebuilt control, and the validator floor it cannot compose
  a value below.
- [[rich-authorization-requests]] — the rules the types editor enumerates instead of validating after
  the fact.
- [[admin-console]] — the console these panes are served in.
- [[admin-mcp-control-plane]] — the second consumer of the admin settings route, which the catalog
  filter bounds identically.

Verified against [[oauth-server-codebase]] as changed by commits `5c45d7f`, `8b86d54` and `a3e93e3`.
