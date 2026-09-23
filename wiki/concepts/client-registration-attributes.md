---
type: concept
title: "Client registration attributes are declared once"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-09-23
---

# Client registration attributes are declared once

Every rule the registration validator applies to a client attribute lives on that attribute's entry
in `lib/consts/client_attributes.ts`. Registration metadata is in `ATTRIBUTES`
(`lib/consts/client_attributes.ts:93`); the base registration keys — `clientId`, `clientSecret`,
`redirectUris`, `applicationType`, `subjectType` — are in `BASE_ATTRIBUTES`
(`lib/consts/client_attributes.ts:418`). The validator in `lib/models/client/schema.ts` applies them
generically, so adding an attribute is one entry.

This replaced five parallel lists — recognised set, defaults, array members, string members,
companions — plus a value-set table and single-attribute passes. Nothing kept those in step, and the
failure mode of a missed entry was an attribute silently ignored: accepted on the wire, absent from
the client, never echoed.

The client itself is unchanged: its registration data is still a flat list, by the same convention as
the configuration keys — see [[feature-flag-gating]].

## Why two tables, not one

The recognised set is `ATTRIBUTES` filtered by capability flags (`recognizedFrom`,
`lib/consts/client_attributes.ts:306`). A base key placed in that table would be recognised as
metadata and projected onto the wire under a snake_case name it has never had. Keeping the base keys
in their own table means no derivation has to remember to exclude them.

## Three things that fail silently if you get them wrong

**Declaration order is the stored key order.** The recognised set is taken in declaration order, and
that order becomes the key order of every projected client and so of every stored record. Two
unconditional attributes sit after the mTLS group rather than with the other unconditional ones for
exactly this reason.

**The two precedence lists are not redundant.** `COMPANION_PRECEDENCE`
(`lib/consts/client_attributes.ts:290`) and `VALUE_SET_PRECEDENCE`
(`lib/consts/client_attributes.ts:356`) decide which refusal a registration receives when it breaks two
rules of the same kind. That is precedence *between* attributes, not a property of any one, so it cannot
live on an entry. The order reproduces what the validator always reported. A rule an entry declares is
applied whether or not it is listed — an omission can reorder a refusal but never drop one. Named
checks need no such list: `FORMAT_RANK` (`lib/consts/client_attributes.ts:78`) orders them by format,
then by declaration, which reproduces the old interleaving. It is a `Record` rather than a list so the
compiler refuses a format with no place in the order, which would otherwise never run.

**The structural layer is deliberately separate.** Types, URL formats, integer bounds and literal
algorithm sets stay in `ClientSchema` (`lib/configs/clientSchema.ts`). So an attribute like
`client_uri` is still described in two layers — its string rule in the table, its web-URI format in the
schema. Folding the schema into the table is the move that, when tried, turned eleven refusals into
silent acceptances: the schema was doing structural validation the table did not replace.

## Base keys are irregular, and the entries say so

"Not sent" means different things for different base keys, so each entry declares its own `absent`
set. An empty string is a refused application type but an absent secret; a null redirect list is
refused as not a list rather than skipped. Refusal text that has always differed from the generic
wording — `must be 'native' or 'web'`, `must be public or pairwise`, `invalid client_id value` — is
stored on the entry verbatim, because that text is protocol surface an integrator reads.

The secret's mandatory-ness is not on its entry. It depends on the client's signing and encryption
algorithms as well as its method, so it is a cross-field rule.

## What stays as code

Rules that are predicates over the whole registration rather than one attribute: the conditional
mandatory rules in `required()` (`lib/models/client/schema.ts:187`), the pairwise-grant rule in
`pairwiseGrantAuthMethod()` (`lib/models/client/schema.ts:307`), and the list in `crossFieldRules()`
(`lib/models/client/schema.ts:431`). Eleven refusals in all, and the complete set.

`pairwiseGrantAuthMethod()` is raised at the moment the authentication method's value set is
consulted, not with the other cross-field rules. That is where it has always fired, and moving it would
change which refusal a registration breaking it and a value-set rule receives.

## The secret and the key set are not one question

It is tempting to unify `needsSecret` with the key-set requirement in `required()`. They look alike —
both scan the method and the algorithm attributes — but they ask opposite things: whether the client
needs **symmetric** material, or **asymmetric** keys. Their attribute sets differ for protocol reasons.
The key-set rule ignores the response signing algorithms, because the server signs those with its own
key, and ignores request-object encryption, which is encrypted *to* the server. The secret rule includes
request-object encryption, because a symmetric key for it derives from the secret. One definition would
conflate them.

## Proven, not asserted

A guard in `test/configuration/client_metadata.spec.ts:2587` enumerates the declaration itself and
proves every declared rule is enforced, so a new entry is covered without anyone writing a case for it.
When first run it found three rules that could never fire: the id-token, introspection and
authorization encrypted-response algorithms required a signing counterpart that is always defaulted
first. They were removed (`lib/consts/client_attributes.ts:286` records why), and a differential corpus
of 33,159 registrations showed no change.

That corpus — every attribute against dozens of values, plus 20,520 registrations breaking two rules at
once, under several configurations and two client shapes — is how the conversion was checked: zero
differences in outcome, refusal text or stored key order. It was itself mutation-tested. Its first
version registered only clients with response types, where the mandatory-redirect rule fires first and
hides the base-key rules, so a mutation to one of them went unseen until a grant-only profile was added.
