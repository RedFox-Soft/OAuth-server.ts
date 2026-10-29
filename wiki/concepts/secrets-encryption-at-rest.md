---
type: concept
title: 'Encryption at rest for stored secrets'
tags: [architecture, security, storage, decision, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-29
updated: 2026-10-29
---

# Encryption at rest for stored secrets

Spec 116. Every secret the server must read back is stored **sealed** with an operator-held keyring: the
plaintext never reaches the database. A secret the server only has to check (a password, a reset link, a
provisioning connection's secret) was already a digest and is unchanged. This is the foundation the token
vault (specs 117-119) stores upstream refresh tokens on.

## What it protects against, and what it does not

- **Against:** a copy of the database without the deployment's secrets: a dump, a backup, a disk snapshot, a
  read-only injection, the operator of a managed database. The admin API already masked these values on read;
  that never protected the database itself.
- **Not against:** an attacker who controls the running server or its environment. They read the keyring as
  the server does.

## What is sealed (`lib/consts/sealed_fields.ts:33`)

Nine leaves: a sign-in provider's client secret and Apple signing key, an application's client secret, the
SMTP password, the private members `d p q dp dq qi` of every signing and encryption key (root and per project),
a person's TOTP secret and a pending enrolment's, the DPoP nonce secret and the error-origin salt.

**A leaf, never the object around it.** `totp` stays an object and `jwk` keeps its shape, so the filters that
test `totp` is an object (both backends' user stores) and the `StoredJWK` schema `documentOf` checks inside the
stores keep working. No secret is used in a query or an index, so randomised encryption breaks no lookup.

**Deliberately plaintext** (`DECLARED_PLAINTEXT`, `lib/consts/sealed_fields.ts:98`), each with its reason:

- **The pairwise identifier salt.** Encrypting it gains almost nothing against a database copy, which already
  holds every account. A lost key would change every relying party's `sub` for ever, turning a recoverable
  loss into an unrecoverable one. Ory Hydra keeps it in configuration instead, which is the way to revisit it.
- **Digests and password hashes**, which are already irreversible.

`test/sealing/inventory_sweep.spec.ts` fails for a secret-looking schema field that is in neither list.

## The format (`lib/sealing/seal.ts:14`)

`fxsealed.` + a `jose` JWE in compact serialisation, `alg: dir`, `enc: A256GCM`. AES-256-GCM, a fresh IV per
value.

- **The protected header** carries `kid` and `bnd`. The binding is built by `bindingOf`
  (`lib/consts/sealed_fields.ts:169`) from identifiers that never change: client id, bucket id + provider id,
  key `_id`, user id, singleton name.
- **Binding.** GCM authenticates the header, so a value copied into another record fails to open there
  (`test/sealing/tampering.spec.ts`).
- **The prefix** tells sealed from plaintext during an upgrade without parsing.
- **Byte secrets.** The two byte singletons store the UTF-8 bytes of the sealed string in their existing
  `bytea`/`Binary` field, so no schema changed.

## Where sealing happens: decorators over the stores

`lib/adapters/index.ts` wraps every store that holds a declared leaf (`sealedModelAdapter`, `:354`, and the
`sealed*Store` calls). A write seals, a read opens. Code above the stores reads plaintext; the three backends
store whatever they are given. A writer that goes through a store cannot forget to seal, and the whole test
suite runs over sealed storage, because `test/test_helper.ts` sets a fixed keyring in `forgetProcessState`.

**A delegate, not a Proxy** (`lib/sealing/decorators.ts:41`). Bun's `spyOn` on a Proxy installs a spy that the
get trap never returns, so `spyOn(store, 'update')` silently stopped counting. The decorated object has its own
methods instead, and each looks the store's method up at call time, so a spy on either object is the one that
runs.

## An unreadable value is absent, never a placeholder (`lib/sealing/decorators.ts:131`)

A leaf that fails to open is removed from what the read returns and recorded for the status. Every consumer
already refuses an absent secret:

- **Client.** A client whose secret is unreadable is unknown to the protocol, so it gets `invalid_client` like a
  wrong secret. `tryFindClient` checks `unreadableFieldsOf` (`lib/models/client/validate.ts:177`), because
  otherwise validation answered `invalid_client_metadata`. The console still reads the client, since rotating
  the secret is the repair.
- **Provider.** `clientCredential` throws `missing_secret`, which shows the "not fully configured" page.
- **TOTP.** Refused like a wrong code (`lib/totp/verify.ts:96`), never skipped.
- **SMTP.** A mailer with a user and no password is not configured.
- **Signing keys.** A key whose private members are absent still verifies but never signs or decrypts
  (`lib/keys/issuer_keys.ts:94`). When an algorithm's signing key is unreadable, a published key of that
  algorithm signs instead.
- **Singletons.** An unreadable singleton reads as zero bytes, which every caller finds unusable and replaces.
  The DPoP resolver already did that; the error-origin salt now does it too (`lib/error_store/redact.ts:58`).
  The replacement is recorded, because old error records stop correlating with new ones.

**Why no placeholder.** A placeholder string would flow into a comparison or a credential: a placeholder client
secret would authenticate whoever presented it.

**The cost.** A write that rewrites the containing record drops the unreadable value: a provider edit rewrites
the whole `federation` array, and a client update spreads the stored record. That turns "unreadable" into
"absent", whose repair is the same.

## The keyring (`lib/sealing/keyring.ts`)

The keyring is JSON: `{v: 1, write, keys}`. `write` names the key new values are sealed with. Every other key is
readable and never written with, which is all a two-step rotation needs.

**Read once, at import** (`:131`), from `KEYRING` or the file at `KEYRING_FILE` (default
`keyring/foxauth.keyring` under the working directory). Both at once is refused. A malformed keyring is refused
with a reason that never echoes a key.

**Under `NODE_ENV=test` neither source is read.** The default path points at a directory nobody creates
(`:118`), so a spec can never write a developer's keyring, nor read one.

**The keyring is a deployment secret**, of the same kind as the connection string. The owner's rule against
environment variables for features does not apply to it. Production and conformance keep it in Infisical; the
Fly.io secret sync delivers it.

**Fingerprints.** The database keeps a fingerprint per key id: the first 16 bytes of
`HMAC-SHA256(key, "foxauth keyring fingerprint v1")` (`:195`). `keyringChecked` (`lib/sealing/startup.ts:32`)
compares the keyring against them before the first seal or open. It runs **inside the decorators**, because the
DPoP secret is opened while configuration is still being imported, long before `lib/index.ts:298` awaits the
same check. A known id with different material therefore refuses the start before anything is written.

## Generating a keyring (`lib/sealing/generate.ts:58`)

The server never generates a keyring silently at startup. That is the n8n failure: a key regenerated inside a
recreated container makes every stored credential unreadable.

**Where it is generated.** First-run setup (`lib/admin/auth/setup.ts`) generates one, with no way to opt out,
and so can a super administrator in the console (Keys, "Encryption at rest").

**Written only into a directory that already exists** (`writtenToFile`, `:31`), with `wx` and mode `0600`. The
server cannot tell a mounted volume from a container's writable layer; a directory someone created or mounted is
the one signal that the place survives a restart. Production on Fly has no volume and gets `KEYRING` instead.
The Compose files mount `foxauth-keyring` at `/app/keyring`.

**Otherwise it is only shown**, and is not used until the deployment supplies it. Using it before then would
seal values under a key the next restart forgets.

**The setup screen** shows the keyring once, with Copy and Download, and continues only after the box "I have
saved this key apart from my database backups" is ticked. The person is not signed in yet, so the confirmation
uses a one-time token, stored as a digest (`POST /admin/api/setup/keyring-confirmation`, `:82`). A wrong, used
or absent token gets one answer.

## The encryption pass (`lib/sealing/pass.ts:106`)

The pass walks every declared leaf as stored, through `getSealingStore()` (`lib/adapters/index.ts:615`):

- **Plaintext** is sealed.
- **A value under a readable key that is not `write`** is sealed again under `write`.
- **A value that cannot be opened** is counted and listed.

**Compare-and-set.** Each change is `sealAt(target, observed, next)` on that one leaf. The ordinary writes
rewrite whole records, so a pass that wrote records back would undo an edit made between its read and its
write (`test/sealing/pass.spec.ts`).

**Not a declared migration.** Its effect depends on a keyring that the migration gate cannot see.

**When it runs:**

- at once, when a keyring is generated and put to use;
- **ten minutes after start** otherwise (`PASS_DELAY_MS`, `:36`). Production deploys blue-green, and the
  previous release reads a sealed value as plaintext: a client secret that no longer matches, an authenticator
  that stops agreeing;
- in count-only mode at start when there is no keyring but fingerprints exist.

A `ReplayDetection` claim keeps two processes from walking at once. It cannot be the migration lease, whose
fixed id would block `db:migrate`.

## Status, MCP, recovery

**Status.** `GET /admin/api/keyring` (super administrators) derives the status from the keyring, the stored
report and what this process failed to open since start. It is published to MCP as `keyring_status_get`.
Generation and backup confirmation are withheld from MCP: generation returns key material, and the confirmation
attests something only a person can.

**Root keys.** Root signing keys that cannot be opened lock the console, because its sign-in is signed with
them. `bun run admin:replace-root-keys` (`lib/sealing/replace_root_keys.ts:19`) revokes each one the way the
console does, which promotes a readable standby or generates a fresh signer.

**CLI.** `bun run keyring new|add|write|remove|show` changes a keyring outside the server and never touches the
database.

## What it costs

Measured on 2026-10-29: 1,000 `client_secret_basic` token requests in process, on the memory backend, with the
validated-client cache cleared every 100 requests (quickstart section 7). With a keyring, p50 was 0.42 ms and p95 0.60 ms.
Without one, p50 was 0.11 ms and p95 0.17 ms. The difference, about 0.3 ms at p50 and 0.43 ms at p95, is one
AES-GCM decryption through WebCrypto on each client read. It is under the 1 ms bound of SC-007, and it is
small next to a real datastore round trip.

## Gotchas met while building it

- **`seedClient` races its own sealing write.** The test helper used to seed without awaiting, and sealing is
  asynchronous: the next bootstrap's `TestAdapter.clear()` ran first, and the write brought the client back
  ("duplicate client_id"). The helper now writes the plaintext record synchronously, starts the sealing write,
  and bootstrap awaits every pending one before clearing and after seeding.
- **Error records are assembled asynchronously.** The origin key is now sealed, and opening it takes more than
  a microtask, so `flushForTest` returned before the record existed. Assemblies are tracked
  (`lib/error_store/queue.ts:140`) and flushed first.
- **The constitution said client secrets MUST be hashed.** They cannot be: `client_secret_jwt` and HS*/A*KW
  derive from the secret. The clause was amended to "hashed, or encrypted at rest where the protocol needs the
  value back" (constitution 3.3.0).
- **No telemetry field.** The usage report's `storage` is a scalar, and a new top-level field would need
  FoxTrust's receiver to accept it first. Until then every report would be answered 422 and lost.

## Related

- [[signing-keys]]: where the sealed private members live.
- [[admin-provisioning]] and [[first-run-setup-had-two-surfaces]]: setup now ends with the keyring step.
- [[pairwise-identifier-salt]]: the one secret left plaintext, and why.
- [[instance-telemetry]]: why the report says nothing about encryption.
