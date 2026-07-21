# Admin Settings — Accordion UI Redesign

**Status:** Design · **Date:** 2026-07-21 · **Depends on:** SP-4 (server-settings editor)

## 0. Context

SP-4 shipped the server-settings editor (`lib/admin/ui/pages/Settings.tsx`) as a flat set of
per-group Cards where every setting in a group is always visible. This makes disabled features
show irrelevant detail controls. This change adds progressive disclosure: a feature's detail
sub-settings appear only when the feature is enabled, via an accordion.

This is a UI-only enhancement plus one additive, UI-only catalog metadata field. The settings
API, validation (including the boot-safety merged-config checks), and the restart-required
banner are unchanged.

## 1. Goal & non-goals

### Goal
Restructure the Settings page so each feature's detail settings are revealed only when that
feature is enabled, using an antd `Collapse` accordion whose panels expand/collapse with the
feature's enable toggle.

### Non-goals
- No change to `lib/admin/settings/routes.ts`, the validation, the GET/PUT contract, or the
  restart-required banner.
- No change to which keys are editable (the catalog membership is unchanged).
- No server use of the new `dependsOn` field — it is UI-only metadata.

## 2. Catalog metadata (`lib/admin/settings/catalog.ts`)

Add one optional field to `SettingDescriptor`:

```ts
dependsOn?: keyof typeof ApplicationConfig;   // the controlling boolean flag
```

Set `dependsOn` on each **detail** descriptor to its group's enable flag (every relationship is
intra-group; the controlling key is always a boolean `.enabled`):

| Detail key | dependsOn |
| ---------- | --------- |
| `par.allowUnregisteredRedirectUris` | `par.enabled` |
| `dpop.requireNonce`, `dpop.allowReplay` | `dpop.enabled` |
| `jwtIntrospection.enabled` | `introspection.enabled` |
| `jwtUserinfo.enabled` | `userinfo.enabled` |
| `mTLS.certificateBoundAccessTokens`, `mTLS.selfSignedTlsClientAuth`, `mTLS.tlsClientAuth` | `mTLS.enabled` |
| `deviceFlow.charset`, `deviceFlow.mask` | `deviceFlow.enabled` |
| `ciba.deliveryModes` | `ciba.enabled` |
| `requestObjects.requireSignedRequestObject` | `requestObjects.enabled` |
| `registration.issueRegistrationAccessToken` | `registration.enabled` |
| `registrationManagement.rotateRegistrationAccessToken` | `registrationManagement.enabled` |

Primaries (the `.enabled` toggles) and the Discovery array settings (`scopes`, `acrValues`,
`clientAuthMethods`) have **no** `dependsOn`. Note `registrationManagement.enabled` and
`richAuthorizationRequests.enabled` are their own group's primaries (not details) — their
prerequisites (`registration.enabled` / `resourceIndicators.enabled`) are enforced only by the
server's merged-config validation, not by `dependsOn`.

## 3. UI (`lib/admin/ui/pages/Settings.tsx`)

Derive from the catalog at render time:
- **primaries** = descriptors with no `dependsOn`.
- **details** = descriptors with `dependsOn`, grouped by their `group`.

Render three sections:

1. **Toggle rows** — boolean primaries whose `group` has no details (JARM, FAPI, client
   credentials, dev interactions, backchannel logout, encryption, revocation, RP-initiated
   logout, claims parameter, resource indicators, RAR): a compact list of `Switch` + label +
   description rows.
2. **Accordion** — an antd `Collapse` with one panel per `group` that has details (PAR, DPoP,
   Introspection, UserInfo, mTLS, Device Flow, CIBA, Request Objects, Registration, Registration
   Management). Each panel:
   - Header: the group's primary label + its enable `Switch` in the panel `extra` slot, with
     the switch's click handler calling `stopPropagation` so toggling does not also toggle the
     panel's expand state.
   - Body: the group's detail controls, each rendered only when its `dependsOn` value in the
     current form state is `true`.
   - Expanded state (`activeKey`) is derived from the primary's current value: enabled →
     expanded, disabled → collapsed. Users do not manually expand a disabled feature.
3. **Discovery Card** — the three array settings, always visible (no enable flag).

Controls per `type` are unchanged from SP-4 (`Switch`/`Select`/`Input`/tags-or-multiple
`Select`). Each field still shows its `description` as help text. The Save button and the
restart-required `Alert` banner are unchanged.

### Cascade-on-disable

When a primary feature toggle is switched **off**, every **boolean** detail whose `dependsOn` is
that primary is reset to `false` in the form state before/at the same time as the primary is set
false. This keeps the persisted set self-consistent and prevents the trap where a hidden but
still-`true` dependent (e.g. `jwtIntrospection.enabled` after `introspection.enabled` is turned
off) causes the server's merged-config validation to reject Save with a 422 the user cannot see
the cause of. Non-boolean details (`deviceFlow.mask`, `deviceFlow.charset`, `ciba.deliveryModes`)
are left unchanged — the boot checks either ignore them while the parent is off or (for
`ciba.deliveryModes`) validate them regardless of the parent, so no reset is needed or wanted.

## 4. Testing

- **Catalog (`test/admin/settings_catalog.spec.ts`):** extend with a `dependsOn`-integrity
  assertion — every descriptor that has `dependsOn` references a key that (a) exists in
  `ApplicationConfig`, (b) is itself a catalog descriptor of `type: 'boolean'`, and (c) shares
  the same `group` as the dependent.
- **Routes:** unchanged; existing `settings_routes.spec.ts` continues to pass (the server does
  not read `dependsOn`).
- **UI:** no unit tests (per the SP-4 pattern) — verified by `bun build.ts` + `bun run
  typecheck` + a manual authenticated check that panels expand on enable, collapse/hide details
  on disable, cascade-reset works, and Save still persists with the restart banner.

## 5. Module layout

```
lib/admin/settings/catalog.ts        ← + dependsOn field + values on detail descriptors
lib/admin/ui/pages/Settings.tsx      ← accordion restructure (toggle rows + Collapse + Discovery) + cascade
test/admin/settings_catalog.spec.ts  ← + dependsOn-integrity test
```

## 6. Risks

- **Stale hidden values on Save:** addressed by cascade-on-disable for boolean details; documented
  above for the non-boolean cases where no reset is needed.
- **Catalog/UI coupling:** the section split is derived purely from `dependsOn` presence and
  `group`, so adding a future setting only requires correct catalog metadata, no UI edits.
