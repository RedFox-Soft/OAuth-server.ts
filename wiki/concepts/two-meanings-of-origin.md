---
type: concept
title: 'The two meanings of origin'
tags: [gotcha, contract, architecture]
sources: [oauth-server-codebase]
created: 2026-09-02
updated: 2026-09-02
graph:
  node_type: concept
---

# The two meanings of origin

Two different things in the fault-reporting path are called `origin`, and they mean opposite kinds of
"where". Confusing them is the one mistake in this area that would be both easy and expensive.

| Path | Type | Meaning |
|---|---|---|
| `ErrorOccurrence.origin` (`lib/adapters/types.ts:487`) | `ErrorOrigin` — `{file, line, frame}` | where in **the server's source** the fault arose |
| `ErrorRecord.origin` (`lib/adapters/types.ts:443`) | `string \| null \| 'not-captured'` | the **caller's network address**, at the configured redaction level |

Both reach the outbound event, under deliberately different names:

- `SentryFailureEvent.origin` is the **network** one, and has shipped since spec 034.
- `SentryFailureEvent.codeLocation` is the **code** one, added by spec 035.

The naming is not tidiness. `origin` was already leaving the server meaning the caller's address, so
repurposing it for the code location would have left every operator's saved filter working and
quietly meaning something else — the worst available failure, because nothing would look broken. The
clearer end state (rename the network one to `callerOrigin`, free `origin` for the location) was
considered and rejected: it is a breaking change to a field a third party already indexes.

`lib/sentry/event.ts` therefore projects from *two different sources* on adjacent lines —
`record.origin` into `origin`, `occurrence.origin` into `codeLocation`. That is correct and must not
be "simplified".

## Why the code location is sendable at all

Because no stack is ever kept. `parseOrigin` in `lib/error_store/fingerprint.ts:23` pulls out the file,
line and function and discards the rest, and the discarded part is the one that matters: a stack's
first line is the error message, and an interpolated message is the likeliest way a token or a secret
reaches a diagnostic record by accident.

So the location is the one form of "where" already known to carry no request data — which is what
makes it sendable while a raw stack, a serialized `Error`, or any frame still carrying the message
remain forbidden. `test/sentry/redaction.spec.ts` asserts this by searching serialized envelopes for a
frame signature (`.ts:line:col`); anchor such a check on the file extension, because a bare
`:\d+:\d+` also matches the envelope header's own time of day.

## The permitted list is enforced at two levels

`unpermittedKeys()` in `lib/sentry/event.ts` checks `PERMITTED_EVENT_KEYS` at the top level **and
descends one level into `codeLocation`** against `PERMITTED_LOCATION_KEYS`.

The descent exists because permission that stops at a boundary is not permission: `codeLocation` is
the only field on the event with an interior, and an interior the outer check cannot see is exactly
where a request identifier would end up being added later — shipped to a third party with no test
failing. A missing or non-object `codeLocation` is itself an offence, because an event without one did
not come from `projectFault`, and unknown provenance is the thing being refused.

Deliberately not general recursion. When a second nested field appears it grows a second explicit
branch, and that visibility is the point.

## Adding the location could not affect grouping

Two facts, both worth knowing before touching `send()`:

- `fingerprintOf` (`lib/error_store/fingerprint.ts:69`) **already** hashes `origin.file` and
  `origin.line`. Two faults at different lines on one endpoint have always been distinct groups. They
  were merely indistinguishable to *read*, which is the whole of what spec 035 changed.
- `send()` passes `fingerprint: [event.fingerprint]` — one element, no `{{ default }}`. Sentry's
  grouping algorithm runs only when the client sets no fingerprint or the rules request `{{ default }}`,
  so `message`, `transaction` and `tags` are inputs to nothing but presentation.

Adding `{{ default }}` here to "improve" grouping would hand grouping to an algorithm reading data
this server deliberately does not send. `test/sentry/dispatch.spec.ts` fails if anyone tries.

## Related

- [[error-store-capture-sites]] — where the occurrences these events are projected from come from
- [[error-store-is-not-flag-gated]] — the read surface, and why its flag governs less than it looks
- [[admin-plane-error-shape]] — the other consumer of the same records
