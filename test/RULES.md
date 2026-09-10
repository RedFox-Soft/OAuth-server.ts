# How tests are written here

The rule is Constitution Principle V, and it is non-negotiable. This file is the working form of
it: what to do when writing a test, what to do when you find one that breaks the rule, and what a
reviewer checks on a pull request.

There is no machine check for any of this, and that is deliberate — see [Why nothing enforces this
in code](#why-nothing-enforces-this-in-code) at the bottom.

---

## The rule

**A test proves a User Case or a Security Invariant. It does not prove that the code is the code it
is.** A test that proves neither is **removed**. Citing the principle is sufficient justification;
no further argument is required and none may be demanded.

**User Case** — an outcome an identifiable audience depends on, stated from outside the system:
what someone tried to do, and what they observed. Four audiences, all equal:

| Audience          | Who it is                                             |
| ----------------- | ----------------------------------------------------- |
| **End user**      | the person authenticating                             |
| **Client**        | the application integrating against the protocol      |
| **Administrator** | the operator running the instance                     |
| **Agent**         | the AI acting through the management surface (`/mcp`) |

**Security Invariant** — a property that must hold regardless of what a caller does. Most often a
refusal: the request that must not succeed, the secret that must not appear, the token that must not
be accepted. Adversary-facing rather than audience-facing. It **may** be proved below the public
surface where that is the only place it is observable — a constant-time comparison is the standing
example — and must not be removed merely for sitting close to what it tests.

**A refusal is an outcome.** In this product the error responses are normative protocol surface: the
RFC 6749 §5.2 shapes, the specific error codes, the `authorization_pending` / `slow_down` polling
semantics. Proving that a spent authorization code yields `invalid_grant` rather than a 500 is a
first-class user case, not an edge case admitted by exception.

---

## Before you write one: two questions, both must pass

### 1. Can you state it in one of the two templates, without naming an implementation symbol in the trigger?

- **behavioural** — _`<outcome>` when `<condition>`_, with shared context carried by the enclosing
  `describe`;
- **completeness** — _for every `<member of a set>`, `<property>`_, where the set is either
  **enumerated from the running system** (a drift guard) or **generated over an input domain** (a
  property-based test, `test/properties/`).

There are two templates rather than one because a test that enumerates a surface has no trigger, and
forcing behavioural prose onto it would delete exactly the tests worth keeping.

A test fitting neither template proves code. `expect(mcpCatalogue.length).toBe(65)` fits neither: it
names no set and no property, it fires identically on a legitimate addition and on a mistake, and
its repair is always to edit the number.

### 2. Does the outcome matter to one of the four audiences, or to an attacker?

This is the half that gets skipped. _"A console notice is prefixed `oidc-provider NOTICE:`"_ passes
question 1 and fails here: it is articulable, but nobody outside the code depends on a log prefix.
That test existed, and was deleted.

### Worked examples

| Statement                                                             | Verdict                                                                           |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| _a public client that omits a code challenge is refused_              | ✅ Security Invariant — actor and action in the trigger, attacker is the audience |
| _for every mounted state-changing admin route, an audit entry exists_ | ✅ completeness, operator audience — the defect is the route somebody forgot      |
| _the escaping helper returns `'false'` for `false`_                   | ❌ the trigger can only be "when the helper is called" — question 1 fails         |
| _a console notice is prefixed `oidc-provider NOTICE:`_                | ❌ articulable, no audience — question 2 fails                                    |
| _the catalogue has 65 entries_                                        | ❌ fits neither template; a change-detector                                       |

---

## Completeness guards are not a third category

A guard that enumerates a surface is a **User Case** when its audience is the operator and a
**Security Invariant** when its audience is the attacker. It is admissible because an example cannot
prove an absence: a behavioural test proves that _a given_ route is audited, never that _no_ route is
unaudited.

Two things about them are easy to get wrong, and both cost a debugging session here:

- **Enumerate the running system, not the source text.** `test/admin/audit_route_classification.spec.ts`
  reads `elysia.routes` off the constructed application. Rename every handler and it stays green;
  mount one unaudited route and it fails. A guard that greps source proves something about text.
- **A change-detector can sit _inside_ a real guard.** The two-way parity assertion in
  `test/mcp/catalogue_drift.spec.ts` is admissible; the length assertion two lines above it was not.
  This is why classification runs per case and never per file.

"User Case" must not be read as "an HTTP request".

---

## Naming and shape

- One action per case. **Two triggers means two cases.**
- The name states the **outcome in the present tense**, plus the **condition wherever the outcome is
  conditional**: `refuses …`, `returns … when …`, `lands in the query of a redirect_uri that carries
no path`.
- The connective is free — `when`, `while`, `after`, `unless`, `with`, `without`, `for`, `on`. The
  word "should" is neither required nor forbidden.
- Neither the name nor the enclosing group may name a symbol of the implementation.
- Given/When/Then belongs in the spec document, not in the code — the `describe` carries the context.
  **No BDD tooling.**

## Declare what a file proves

Every spec file opens with one sentence, immediately above its top-level `describe`:

```ts
/**
 * @proves A spent authorization code is refused with invalid_grant, and the grant it belonged to
 * is revoked rather than left usable.
 */
describe('authorization code, second use', () => {
```

The tag must be the **first content line** of a JSDoc block. Its purpose is that a reviewer can see
the file's claimed intent before reading a single assertion, and that a spec cannot arrive with no
stated reason to exist.

It lives in the file it describes and **nowhere else**. There was briefly a generated index of all
277 declarations; it was deleted, because it was a second copy of every sentence and therefore a
second thing to keep in step — and keeping it in step needed a drift check, which is the code
enforcement this document exists instead of.

The declaration is per **file**, and carries no category. A category per file was specified and then
abandoned: 206 of 277 files contain both user cases and security invariants, so it would have read
"both" on three files in four. The category belongs to the case and is carried by its name.

---

## Finding a test that breaks the rule

**Re-anchor before deleting.** A test that proves nothing as written, but whose subject matter is
real, is moved to the surface where the behaviour is observable. Deletion is admissible on exactly
two grounds:

1. it proves nothing observable at all, or
2. it is a demonstrated duplicate of a **named** surviving test.

**Effort is not a ground.** A test that is expensive to re-anchor is re-anchored.

If the subject matter is real but there is no covering test and you are not writing one now, record
it in [`../Task.md`](../Task.md) rather than deleting silently. That file is why we know about the
constant-time comparison with no timing test, and about the two defect classes that look covered
and are not.

---

## Where a test may run

Principle III governs this and it is separate from Principle V — one answers _where_, the other
_what for_.

- `bun test` is the merge gate and **never touches a real database**. In-memory adapter only.
- The fidelity suites (`database/verify_postgres.ts`, `database/verify_migrations.ts`) need a real
  server and are **scripts, not specs**, precisely so the default run cannot reach them.
- Coverage a database-free test can provide **must not** be moved into that tier. Under Principle V
  that prohibition has a second motive: relocating a test there is also a way to make a deletion
  look free.

---

## Reviewing a pull request

For each test added or changed, in order:

1. **Read its name.** Does it state an outcome, and a condition where the outcome is conditional?
   Does it name an implementation symbol? A name like `validates the helper` is the signal to look
   harder, not a style nit.
2. **Apply the two questions.** Template, then audience. Most inadmissible tests pass the first and
   fail the second — ask _who observes this_ and require an answer from the four audiences or the
   attacker.
3. **One action per case.** A case asserting two triggers is two cases.
4. **New spec file?** It must carry a `@proves` declaration. A declaration that restates the file
   name is not a declaration — it must say what somebody outside the code observes.
5. **Deletion in the diff?** It needs one of the two grounds, in the commit message. A duplicate must
   **name** its survivor. "This was slow / awkward / in the way" is not a ground.
6. **Length or count assertion?** `toBe(<number>)` on a collection size is a change-detector unless
   it is the non-emptiness check of a quantified claim — a guard asserting `length > 0` so that
   for-every over an empty set cannot pass vacuously is fine; `toBe(65)` is not.
7. **Guard added?** Confirm it enumerates the constructed application, not source text.

Report findings as: the case name, which question it fails, and whether the fix is a rename, a
re-anchor, or a deletion.

---

## Why nothing enforces this in code

There was a machine guard — `test/intent/declaration.spec.ts` — requiring a `@proves` declaration in
every spec file. It was removed, and the reason is worth keeping, because it is the rule applied to
itself.

Principle V opens "every test in the suite", and that guard was in the suite. Apply its own admission
test to it: question 1 passes, because it enumerated a set from the running system. Question 2
**fails** — the four audiences are the end user, the client, the administrator and the agent, and
none of them depends on whether a spec file declares its intent. The party that benefits is the
future maintainer. That is structurally the same as the console-notice prefix, which the rule deletes.

It also had the failure mode of its kind. It asserted only that a declaration was _present_ and
longer than twenty characters, and a page of source code satisfies both — which is exactly what
happened: its pattern matched the `@proves` inside its own regular expression, captured forty lines
of code as the "declaration", and the guard passed itself for the wrong reason. A drift check on a
generated document caught it, not the guard.

The working notes that refactor produced — the per-case register, the gap list, the measurements —
were deleted with it, for the same reason: a monument to a finished piece of work is not something
anybody reads, and the nine findings worth keeping moved to [`../Task.md`](../Task.md). What remains
is this document, the `@proves` sentence in each file, and review.

A guard can tell you a sentence exists. Only a reader can tell you the sentence is true.
