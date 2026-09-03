---
type: concept
title: 'A user-code mask with no random part'
tags: [config, contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-09-03
updated: 2026-09-03
graph:
  node_type: concept
  relationships:
    - predicate: constrained_by
      object: concept:feature-flag-gating
      source: oauth-server-codebase
      evidence: "Both mask checks sit inside the enable guard — lib/configs/configuration.ts:530: 'if (config[...deviceFlow.enabled...]) {' — so a disabled flow's junk mask is not a boot failure."
      confidence: high
      status: current
    - predicate: complements
      object: concept:settings-console-descriptor
      source: oauth-server-codebase
      evidence: "The validator refuses a mask with no asterisk (configuration.ts:557) and the console stops one being composed, asking for a length and a grouping instead; the comment at 553 names the console as the place the resulting entropy is shown."
      confidence: high
      status: current
---

# A user-code mask with no random part

`deviceFlow.mask` is a **template**, not a format string: `generate` substitutes a random character
for each `*` and copies every other character through verbatim
(`lib/helpers/user_codes.ts:14-23`). The count of asterisks is therefore the entire entropy of a
device user code — `lib/helpers/user_codes.ts:9` derives the number of random characters to draw
from nothing but that count:

```ts
const length = mask.split('*').length - 1;
```

## The validator checked the alphabet and not the shape

`checkDeviceFlow` verified which characters a mask *may contain* — asterisk, hyphen-minus, space
(`lib/configs/configuration.ts:538`) — and never that it contained an asterisk at all. So `"---"`,
`"-  -"` and `""` all passed. With no `*`, `length` is `0`, the `map` copies every character through,
and the "generated" code is the mask itself: **byte-identical for every device that ever pairs**,
from the next restart onward.

This is why it is a security defect and not a cosmetic one. A user code exists so that approving a
pairing requires possession of something the approver was shown; with no random part, guessing it is
not an attack but a reading of the configuration. The path was reachable without touching a file —
the setting is catalogued, the character check accepted the value, and the flow then issued a
constant code.

The fix is one line at `lib/configs/configuration.ts:557`, and its message says why rather than
restating the rule:

```ts
if (!config['deviceFlow.mask'].includes('*')) {
```

## A floor, not a policy

How many asterisks are enough is a judgement an operator makes. The check refuses **zero** only,
because zero is not a weak answer to that question — it is the absence of a code. The comment above
the check states that division deliberately, so a later reader does not "strengthen" it into a
minimum length the server has no basis to pick.

## Why it is scoped to the flow being enabled

Both mask checks live inside `if (config['deviceFlow.enabled'])`
(`lib/configs/configuration.ts:530`), which is where the character check already sat. Widening
either to a disabled flow would **refuse a boot that succeeds today**: a deployment carrying a junk
mask it never uses would stop starting, which is more than a fix for this should do.

The hole still closes at the moment the value starts to matter, and the mechanism is worth knowing
because it is not obvious from either check. The administrative `PUT` validates the **merged**
configuration, so the very submission that switches the flow on is refused while the stored mask
cannot generate a code. There is no ordering in which a live flow reads an unchecked mask.
`test/configuration/device_flow_config.spec.ts` pins the scoping choice rather than leaving it to be
inferred, and demonstrates the consequence through `generate` itself — so the reason the invariant
exists cannot rot away from the invariant.

## The console half of the same problem

A free-text template field asks the operator for the encoding instead of for the decision. Two
consequences followed, and only one of them was the validator's:

- every asterisk is one character of entropy and nothing on the page said so, which made `"****-****"`
  and `"**-**"` look like formatting preferences;
- a mask with no asterisks was accepted by the page as readily as by the validator.

The control now asks for a **length**, a **grouping**, and shows a live example of what a device
would display, with the strength stated in bits beside it — eight characters of `base-20`
(`BCDFGHJKLMNPQRSTVWXZ`, `lib/helpers/user_codes.ts:4`) is about 35 bits, the same eight digits about
27. That comparison is the one the template field made invisible.

Three details of that control are decisions rather than implementation:

- **Stated, not graded.** What counts as enough depends on how fast the verification endpoint refuses
  guesses, which is a rate-limit setting on another pane. The page gives the figure and leaves the
  judgement with the operator — the same division the `risk` tags use
  ([[settings-console-descriptor]]).
- **Only group sizes that divide the length are offered**, since a short final group reads badly and
  is not a shape the editor represents.
- **A mask the editor cannot draw falls back to the template field** — uneven groups, both
  separators, something typed by hand — rather than being redrawn into the nearest supported shape,
  which would silently change what the server issues.

The strength figure is cross-checked in test against the real `generate` rather than against the
arithmetic that produced it, so a code of the promised length is what the mask actually produces.

## Related

- [[settings-console-descriptor]] — the console this control lives in, and why a bespoke editor is
  pinned to `validateConfiguration` instead of restating its rules.
- [[feature-flag-gating]] — the enable flag both checks sit behind, and why a disabled capability's
  settings are not validated.
- [[html-response-security-policy]] — the device user-code input's own gotcha: the `onfocus`
  attribute in `lib/helpers/user_code_form.ts`.

Verified against [[oauth-server-codebase]] as changed by commits `23aa3de` and `8b86d54`.
