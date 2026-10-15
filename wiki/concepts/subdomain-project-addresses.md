---
type: concept
title: 'A project may be addressed by a subdomain of the instance'
tags: [architecture, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-10-15
updated: 2026-10-15
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:project-is-an-issuer
      source: oauth-server-codebase
      evidence: 'Before `path`, because a subdomain bucket carries a slug too: tested the other way round, every subdomain bucket would read as path-addressed and mint `<ISSUER>/<slug>`'
      confidence: high
      status: current
---

# A project may be addressed by a subdomain of the instance

Since spec 101 (2026-10-15) a project (stored as a bucket, [[project-is-an-issuer]]) has a third address
form beside a path and a hostname of its own: **a subdomain of the instance**, `<slug>.<instance host>`, where
the instance host is the canonical host of `ISSUER`. With `ISSUER=https://auth.example.com`, the project `acme`
is the issuer `https://acme.auth.example.com`. A project still holds exactly one address.

## Derived, not stored: the slug plus a marker

The record keeps the slug and a marker, `subdomain: true` (`lib/adapters/types.ts:1887`). The full name is not
stored. The reason is in the field's comment: the full name embeds the instance's host, so a stored name would
keep answering beneath the old host after `ISSUER` changed, while a derived one follows `ISSUER` exactly as a
path issuer does. `issuerFor` builds it from `ISSUER`'s scheme and host (`lib/configs/issuer.ts:118-121`), so
the port comes along too, and a development instance on `localhost:3000` serves `acme.localhost:3000`.

The marker is a flag on the slug and not a third name field, for two reasons:

- **The slug stays the project's one name.** Moving between path and subdomain changes no name, only the
  marker. A write is one of two shapes, a slug with an optional marker or a hostname
  (`BucketAddressWrite`, `lib/adapters/types.ts:1973`). A slug written without the marker removes it, so a
  `setAddress` cannot leave a project at two addresses (`:2028`).
- **No data migration.** The marker is absent on every record written before the form existed, and absent
  reads as the form the project already had.

Moving between path and subdomain keeps the slug and the signing keys. Keys are keyed by the project's id,
not its issuer ([[per-issuer-isolation]]). `test/subdomain_projects/address_change.spec.ts:96` proves the
same keys sign after the move.

## The order `addressOf` asks in

`addressOf` (`lib/configs/issuer.ts:42`) tests root, then host, then **subdomain**, then path
(`:50-51`). Subdomain must come before path because a subdomain project carries a slug too. Tested the other
way round, every subdomain project would read as path-addressed: it would mint `<ISSUER>/<slug>` while its
discovery document named its own origin.

A subdomain project is on an origin of its own, like a host project. `hasOwnOrigin` (`:145`) answers "host or
subdomain", and the three places that used to test `bucket.host` now ask it:

- **The session cookie name.** `sessionCookieName` gives the bare `_session` (`lib/consts/param_list.ts:269`).
  The suffix exists only because path projects share one origin ([[cookie-path-scoping]]).
- **The interaction's origin binding.** An interaction begun at an own-origin project may be completed only
  there (`lib/interactions/index.ts:1114`).
- **Where a resumed request returns** (`lib/actions/authorization/resume.ts:82`).

Each of those tests meant "has its own origin" while a hostname was the only way to have one. A subdomain
project has a slug and no host, so a missed site would have taken the path branch: a suffixed cookie on a
private origin, or a resume to the root issuer.

## Resolution, and the one-address rule

`bucketAtHost` (`lib/admin/auth/bucketAddress.ts:197`) asks for an **exact custom hostname first**, then a
subdomain (`:208-210`). The order matters because a hostname given before subdomains existed may look like one,
and it keeps its name. `bucketAtSubdomain` (`:238`) takes the single label directly beneath the canonical host
(`subdomainLabelOf`, `lib/consts/request_host.ts:173`); anything deeper names no project. It answers only for
a subdomain-marked project (`:245`).

Both directions are closed, because two addresses would be two issuer identifiers for one population:

- A **path** project is not served at `<slug>.<instance host>` (`:245`). That name lies beneath the
  deployment's domain and nobody holds it, so it is refused rather than served as the default project
  (`isWithinDeploymentDomain`, `:183`).
- A **subdomain** project is not served at `/<slug>` on the instance host: `bucketAtAddress` refuses it
  (`:271`). The slug still belongs to it, so no other project can take the path.

The marker has to travel wherever a record is cut down to its address. `requestBucketOf` (`:350`) builds the
request bucket for both the request path and `issuingBucket` (`:370`), the record every path uses once it knows
a project id. A subdomain project read back without its marker would be taken for a path. This is the same
defect class as the 2026-09-24 bug in which `issuingBucket` dropped `host` ([[project-is-an-issuer]]).

## Which names a subdomain may not take

A slug already avoids the server's own route names. A subdomain must also pass `assertSubdomainAvailable`
(`lib/admin/buckets/routes.ts:247`). Its checks apply to super administrators too, because they protect names
in the operator's own domain, not a team's quota.

- **Reserved labels.** `RESERVED_SUBDOMAIN_LABELS` (`lib/consts/reserved_names.ts:77`) lists `www`, `mail`,
  `api`, `login`, `status` and the like. It is separate from the path list because the two protect different
  things. A path name keeps a project from shadowing a route, so `www` is harmless as `/www`. As
  `www.auth.example.com` it would be a name in the operator's domain under a tenant's control, and these are
  the names a phishing page would most like to borrow.
- **The encoded-label shape.** `hasEncodedLabelShape` (`:117`) refuses `--` as the third and fourth
  characters. That is the shape RFC 5891 §4.2.3.1 reserves for encoded names such as `xn--…`, which a browser
  may display as other characters. As a path, which nobody renders, the same slug is accepted
  (`test/subdomain_projects/assignment.spec.ts:103`).
- **`projects.reservedHostnames`** applies to the full name `<slug>.<instance host>`.
- **A slug and `<slug>.<instance host>` are one name, in both directions.** A subdomain is refused when another
  project holds that full name as its hostname. A hostname one label beneath the instance is refused when that
  label is another project's slug in either form, because a path project can move to its subdomain later
  (`assertHostAvailable`, `:305`, the label check at `:356`).

## The slug is now unique in storage

Until spec 101 a slug was unique only by a read-then-write check in the handler (`assertSlugAvailable`,
`lib/admin/buckets/routes.ts:133`), so two concurrent creates with one slug both succeeded. Once a slug can be
an origin, that is two projects claiming one origin. `userBuckets` now has a unique sparse index on `slug`
(`lib/consts/storage_inventory.ts:671`), beside the one on `host`. It is sparse because a host project holds
no slug.

- **Applied by `db:setup`/`db:setup:pg`, with no migration, after a pre-check.** Both scripts first look for
  slugs that more than one project already holds (`duplicateSlugReport`, `database/provisioning_report.ts:93`;
  called at `database/mongodb.ts:183` and `database/postgres.ts:255`). If there are any, they print the whole
  list and provision `userBuckets` without its unique constraints (`blockUnique`, `database/mongodb.ts:200`,
  `database/postgres.ts:262`), and the run exits 1. Otherwise the index build would abort on the first offending
  value it met. Duplicates are reported and never resolved: a slug is part of an issuer identifier, so the
  operator decides which project keeps it, using the address-change route.
- **Each backend names the field.** MongoDB reads the duplicate-key error's `keyPattern`
  (`duplicatedField`, `lib/adapters/mongodb/userBucketStore.ts:51`). PostgreSQL's client does not reliably
  report the index, so the losing write asks which of its names another project holds (`takenName`,
  `lib/adapters/postgres/userBucketStore.ts:176`). The memory adapter emulates the index (`slugHolder`,
  `lib/adapters/memory/userBucketStore.ts:31`). The route turns the result into a 409 naming the field
  (`refusingATakenName`, `lib/admin/buckets/routes.ts:382`). Proved by
  `test/subdomain_projects/assignment.spec.ts:149`.
- **A stored `slug: null` is removed first on MongoDB.** A sparse MongoDB index skips documents that lack the
  field, but it still indexes a stored `null`. Before 2026-09-28 the Mongo store wrote `undefined` as `null`, so a
  host project created between 056 and then holds `slug: null` ([[stored-document-schemas]]), and two such
  projects would have refused the index. `db:setup` therefore unsets every explicit null slug before it provisions
  the fixed areas (`database/mongodb.ts:163-176`) and logs "removed a stored null slug from N project(s)". A null
  slug is no address and no name, so removing it changes nothing a request or an operator can observe. This
  was verified against a scratch MongoDB: two host projects holding `slug: null` were repaired, and the index
  then built with no constraint skipped. PostgreSQL needs no repair, because its sparse index is partial over
  `IS NOT NULL`.

**One race is accepted.** A super administrator could give some project the custom hostname `s.<instance>` at
the same moment that slug `s` moves to subdomain. The two writes touch different fields, so no index can
close the gap. Resolver precedence still gives the name one holder: the exact hostname is asked first.

## The setting is read when a form is chosen, never while serving

`projects.addressForms` takes `path` (the default), `subdomain` or `both` (`lib/configs/application.ts:393`;
console descriptor at `lib/admin/settings/catalog.ts:526`). It limits teams only. A super administrator is
never limited, and a hostname stays super-administrator-only whatever the value.

- **Why `path` is the default.** A subdomain answers only once the operator has pointed a wildcard DNS record
  and a wildcard TLS certificate at the server, and the server cannot see whether they have.
- **Why it is never read while serving.** It is read only in `addressFormsFor`
  (`lib/admin/auth/can.ts:253`), when an address is chosen. Changing it therefore moves no project. A project
  whose form is no longer offered keeps its address and keeps answering there
  (`test/subdomain_projects/setting.spec.ts:224`), and its team can still move it to a form that is offered.
  Because it is read live, a saved value judges the next request without a restart (`:208`).
- **An omitted form means a path, whatever the setting** (`requestedForm`, `lib/admin/buckets/routes.ts:186`;
  `AddressForm`, `lib/admin/buckets/schema.ts:51`). A request that an existing integration already sends keeps
  the meaning it had. Under `subdomain` only, such a request is refused and the refusal names the setting
  (`setting.spec.ts:114`). The setting does not quietly reinterpret it.

## Why `addressForms` is a list

`GET /admin/api/me` used to carry `can.createHost`, a boolean. Spec 101 replaced it with `can.addressForms`
(`lib/admin/auth/can.ts:52`), an **ordered** list of `path`, `subdomain` and `host`:

- **It can express three forms and a default.** A boolean per form could not say which form to preselect.
  The first entry is the one selected, and the subdomain comes first wherever it is offered. An operator who
  switched it on has the wildcard DNS, and an own origin keeps a project's cookies and pages apart from every
  other project's.
- **It states the full answer.** For a super administrator the list is the team's forms, then the rest, then
  `host`.
- **The route decides through the same list.** `assertMayChooseForm` (`lib/admin/buckets/routes.ts:198`)
  refuses exactly what the list leaves out, before any name is judged, so a caller without the right is not
  told whether the name was free. The console and an agent reading `whoami` therefore get the same answer
  ([[admin-mcp-control-plane]]).

An owner may now change a **path or subdomain** address (`ownerMayReaddress`, `lib/admin/auth/can.ts:126`).
Which form they may move *to* is the list's job, checked by the route ([[project-workspace]]).

## The audit entry records issuers

`bucket.address.change` (shown `project.address.change`) now records `from` and `to` as **issuer URLs**
(`lib/admin/buckets/routes.ts:1249-1251`). A path `acme` and a subdomain `acme` carry the same slug, so an entry
that recorded only the name could not tell that move from no move at all. Entries written before spec 101 keep
a slug or a hostname ([[admin-audit-trail]]).

## What did not change

- **Email links** still point at `ISSUER` for every form (`verifyUrlFor`, `lib/verification/challenge.ts:67`),
  as they already did for a hostname of its own.
- **`namesOwnScimEndpoint`** (`lib/admin/resources/routes.ts:91`) compares a declared resource only against
  `ISSUER`'s origin. A project's built-in SCIM endpoint on its own hostname is therefore not recognised as this
  server's own. That gap already existed for hostnames, and subdomains inherit it. It is a backlog item.

## Related

- [[project-is-an-issuer]] — the address forms, `addressOf`, and why one project has one issuer
- [[per-issuer-isolation]] — keys and namespaces keyed by id, so a move between forms keeps them
- [[cookie-path-scoping]] — why only path projects need a suffixed cookie name
- [[project-workspace]] — who may change an address, and the preview
