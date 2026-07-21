# Admin Panel SP-4 — Server-Settings Editor (super_admin)

**Status:** Design · **Date:** 2026-07-21 · **Depends on:** SP-1 (admin foundation)

## 0. Context

SP-1 built the admin foundation and left **Settings** as a gated "coming soon" stub
(`lib/admin/ui/pages/Stub.tsx`), naming "server-settings editing and the startup-only-config
reload problem" as SP-4 work. Server configuration lives in `lib/configs/application.ts` as
`ApplicationConfig` — a flat map of dotted keys (`'par.enabled'`, `'scopes'`, …) with typed
values (booleans, scalars, arrays, and some structured/function/Buffer values). At module load
it merges persisted overrides over the defaults:

```ts
Object.assign(ApplicationConfig, await configStore.get());   // application.ts:363
```

`configStore` (`AdapterConfigStore`, memory + mongodb) exposes `get()` / `set(config)`.

**The reload problem.** Config is read at two moments:
- **Live, per request** — e.g. `calculateDiscovery()` reads `ApplicationConfig` on every
  discovery fetch (`lib/configs/discoverySupport.ts`).
- **Once, at provider-build time** — response modes (`lib/helpers/initialize_app.ts`), grant
  handlers, and feature middleware/routes are wired at startup from `ApplicationConfig`.

`configStore.set` only persists; nothing mutates the in-process `ApplicationConfig` after boot.
So a saved change cannot fully take effect until the next boot, and hot-mutating the live object
would let discovery advertise capabilities the running provider never wired.

## 1. Goals & non-goals

### Goals
1. A super_admin-only editor over a **curated safe subset** of `ApplicationConfig`, persisted
   through `configStore`.
2. A single **catalog** module describing each editable key — the source of truth for the
   editable whitelist, server-side validation, and UI rendering.
3. **Persist + restart-to-apply** semantics with a clear "restart required" banner driven by
   drift between the persisted (desired) config and the running (boot-time) config.
4. Replace the Settings stub with a real grouped form.

### Non-goals (deferred / out of scope)
- Editing structured/unrepresentable values: `claims` (nested map), `registration.policies`
  (function), `registration.initialAccessToken` (bool|string), `richAuthorizationRequests.types`
  / `.ack`, `dpop.nonceSecret` (Buffer). These remain code/env-managed.
- Hot-applying config to the running process, or programmatically restarting it.
- JWKS/signing-key management (SP-5).
- Deep feature-dependency enforcement in the editor (see §4) — left to boot-time validation.
- Any change to the OIDC protocol surface.

## 2. Reload model (persist + restart)

Saving writes to `configStore` and does **not** mutate the live `ApplicationConfig`. The editor
computes, per editable key:

- `running[k]` = the live `ApplicationConfig[k]` (the boot-time snapshot).
- `desired[k]` = the persisted value if `configStore.get()` has `k`, else `running[k]`.
- `restartRequired` = `true` iff any editable key has `desired[k] !== running[k]`; `changedKeys`
  lists them.

The form displays `desired` (what will take effect). The banner clears only when a later boot's
`ApplicationConfig` matches the persisted config — i.e. the editor cannot detect "an operator
restarted", only that running and desired agree again. This is an accepted limitation.

## 3. Settings catalog (centerpiece)

`lib/admin/settings/catalog.ts` exports an ordered list of descriptors, the single source of
truth consumed by the routes (whitelist + validation) and shipped to the UI (rendering):

```ts
type SettingType = 'boolean' | 'string' | 'enum' | 'string-array';
interface SettingDescriptor {
  key: string;            // an ApplicationConfig key
  group: string;          // UI section, e.g. 'DPoP', 'Device Flow', 'Discovery'
  label: string;
  description: string;    // lifted from application.ts doc-comments
  type: SettingType;
  options?: string[];     // enum members, or the allowed set for a string-array
}
```

Editable keys (~35), grouped by feature:

- **Boolean flags:** `par.enabled`, `par.allowUnregisteredRedirectUris`, `dpop.enabled`,
  `dpop.requireNonce`, `dpop.allowReplay`, `introspection.enabled`, `responseMode.jwt.enabled`,
  `fapi.enabled`, `clientCredentials.enabled`, `devInteractions.enabled`,
  `backchannelLogout.enabled`, `encryption.enabled`, `jwtIntrospection.enabled`,
  `jwtUserinfo.enabled`, `revocation.enabled`, `userinfo.enabled`, `rpInitiatedLogout.enabled`,
  `claimsParameter.enabled`, `mTLS.enabled`, `mTLS.certificateBoundAccessTokens`,
  `mTLS.selfSignedTlsClientAuth`, `mTLS.tlsClientAuth`, `deviceFlow.enabled`, `ciba.enabled`,
  `requestObjects.enabled`, `requestObjects.requireSignedRequestObject`,
  `resourceIndicators.enabled`, `richAuthorizationRequests.enabled`, `registration.enabled`,
  `registration.issueRegistrationAccessToken`, `registrationManagement.enabled`,
  `registrationManagement.rotateRegistrationAccessToken`.
- **Enum:** `deviceFlow.charset` (`'base-20' | 'digits'`).
- **String:** `deviceFlow.mask`.
- **String-array:** `scopes`, `acrValues`, `clientAuthMethods` (options = the five known methods
  from the default), `ciba.deliveryModes` (options = `['poll','ping']`).

## 4. Validation

Catalog-driven, in the PUT handler:
- Reject any submitted key not present in the catalog → 422.
- Enforce the descriptor's `type`: `boolean` must be a bool; `string` a string; `enum` a member
  of `options`; `string-array` an array of strings, and for keys whose `options` enumerate an
  allowed set (`clientAuthMethods`, `ciba.deliveryModes`, and any enum) every element must be in
  that set.
- **Invariant guard:** `scopes` must include `'openid'` → 422 otherwise (removing it breaks OIDC).

Deep feature-dependency combinations (e.g. `jwtIntrospection.enabled` requires
`introspection.enabled`; `mTLS` sub-flags require `mTLS.enabled`) are **not** hard-blocked here —
they are surfaced as advisory helper text in the UI and remain enforced by the provider's
existing boot-time configuration validation (`lib/helpers/configuration.ts`).

## 5. API (`lib/admin/settings/`, super_admin only)

All under `/admin/api/settings`, guarded by `resolveAdmin` + `assertAuth` +
`assertRole('super_admin')`; errors in the SP-1 `admin_error` shape.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/admin/api/settings` | Returns `{ catalog, values, restartRequired, changedKeys }`. `values` = `desired` for every catalog key; `restartRequired`/`changedKeys` computed per §2. |
| PUT | `/admin/api/settings` | Body = a partial `{ key: value }` map of edited settings. Validate per §4; merge into the current stored config (`configStore.get() ?? {}`); `configStore.set(merged)`. Returns the same shape as GET (now reflecting the new `desired` and `restartRequired`). |

The stored config is the merge target: PUT reads current stored, overlays the edited keys, and
persists the result, so unedited overrides are preserved and `desired` = defaults ⊕ stored.

## 6. UI

`lib/admin/ui/pages/Settings.tsx` replaces the stub for the `settings` page (rendered only for
super_admin; the nav item is already super-only from SP-1). `Layout.tsx` renders `<Settings/>`
instead of `<Stub title="Settings"/>`.

- Fetches `GET /admin/api/settings` on mount; renders one section per catalog `group`.
- Controls by `type`: `Switch` (boolean), `Select` (enum), `Input` (string), `Select mode="tags"`
  (string-array; `options` offered as suggestions), each with its `description` as help text.
- A top `Alert` ("Changes saved — restart the server to apply", listing `changedKeys`) shows when
  `restartRequired`.
- One **Save** button PUTs the full edited set, then refreshes state from the response.

## 7. Testing

bun:test + Eden treaty + memory adapters, per SP-1..SP-3 patterns. `configStore` (memory) backs
persistence; reset between tests.

- **Catalog/validation:** unknown key → 422; wrong type (bool given string, enum out of set,
  string-array with a non-member element) → 422; `scopes` without `openid` → 422.
- **GET:** returns the catalog and `desired` values; `restartRequired` is `false` when nothing is
  persisted beyond the running config.
- **PUT:** persists via `configStore` and round-trips (a follow-up GET reflects the new value);
  `restartRequired` becomes `true` and `changedKeys` lists the drifted keys after a change that
  differs from running; unedited stored overrides are preserved across a second PUT.
- **RBAC:** project_admin → 403 on GET and PUT; anonymous → 401.

## 8. Module layout

```
lib/admin/settings/
  catalog.ts        ← editable-key descriptors (SSOT: validation + UI + whitelist)
  schema.ts         ← TypeBox body schema for PUT (partial record of catalog keys)
  routes.ts         ← GET/PUT /admin/api/settings (super_admin only)
lib/admin/index.ts  ← + .use(settingsRoutes)
lib/admin/ui/pages/
  Settings.tsx      ← real editor (replaces the Stub for 'settings')
  Layout.tsx        ← render <Settings/> for the 'settings' page
lib/configs/application.ts   ← unchanged (boot-time merge already reads configStore)
lib/adapters/*/configStore.ts ← unchanged (get/set already exist)
```

## 9. Risks & open questions

- **Restart detection is drift-based (accepted):** the banner reflects desired-vs-running
  divergence, not an actual restart event; it clears when a boot brings them back into agreement.
- **Curated subset drift:** the catalog hardcodes which keys are editable and their types; if
  `ApplicationConfig` gains/loses keys, the catalog must be updated in tandem. The catalog keys
  are typed against `ApplicationConfig` keys so a removed key fails typecheck.
- **Light validation:** invalid *combinations* (dependent features) can be saved and will be
  caught only at next boot by the provider's config validation. Advisory helper text mitigates;
  hard enforcement is a deliberate non-goal for SP-4.
- **`clientAuthMethods` / `scopes` semantics:** these feed discovery derivations
  (`discoverySupport.ts`); since discovery reads live at runtime but the editor persists for next
  boot, an edited value only appears in discovery after restart — consistent with the reload
  model, but worth noting so it isn't mistaken for a bug.
```