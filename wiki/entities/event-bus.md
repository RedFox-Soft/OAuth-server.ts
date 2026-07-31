---
type: entity
kind: subsystem
title: "eventBus (lib/event_bus.ts)"
aliases: [provider, event_bus]
tags: [architecture, gotcha]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-07-31
graph:
  node_id: subsystem:event-bus
  node_type: subsystem
  canonical: true
---

# eventBus (lib/event_bus.ts)

The server's lifecycle event emitter, and — deliberately — nothing else:

```ts
export const eventBus = new EventEmitter();
```

Actions emit, deployments subscribe. That is the entire contract, so a bare `EventEmitter` is the
entire implementation: no init step, no construction step, nothing to configure.

## It used to be the provider

The module was called `provider` until it stopped being one. Inherited from `oidc-provider`, a
`Provider` instance owned the configuration, the routes, the model classes and the signing keys, and
was constructed per deployment. Every one of those responsibilities now lives with the module that
implements it, and what remained of the class was the event emitter it extended.

Where the responsibilities went:

- Settings → `ApplicationConfig` / `configuration` ([[feature-flag-gating]]), `ClientDefaults`, or the
  addon registry.
- Signing keys → module state in `configs/keystore.ts`.
- Model classes → direct exports; there are no class getters to reach through
  ([[token-payload-access-contract]]).
- Client identity → `adapter('Client')` ([[client-identity-from-database]]).

This is why documentation or code that constructs a provider, or reads model classes off it, is
describing the pre-`e37d4c9` shape of the server. CIBA delivery moved out of it in the same
refactor.

## Two constraints that look like accidents

**It imports the key store for its side effect.** `import './configs/keys.js'` sits at the top not
because the bus needs keys, but because reading the key store is asynchronous and this is the
highest module every entry path imports that does not itself start a server (`lib/index.ts` calls
`.listen` at module scope). Other modules reach `configs/keys.ts` incidentally, but nothing
guarantees a given entry path touches one — without this line, importing the bus alone leaves a
server holding no signing keys. Covered by `test/boot/boot_state.spec.ts`.

**It must import no model.** The module is a leaf, and keeping it one is load-bearing. It previously
needed an explicit `import './models/id_token.js'` anchor because it pulled in `Client` and `Grant`
for `backchannelResult`, which made it a participant in the
`base_token` → `base_model` → `event_bus` cycle; entering that cycle here left `base_token`
half-initialised and `grant.ts` threw `Cannot access 'BaseTokenPayload' before initialization`.
Moving `backchannelResult` to `actions/authorization/backchannel_result.ts` made the module a leaf,
so `base_model` → here terminates and the anchor is gone. The source comment ends: "Keep it that
way."

## Known signals

- `feature_disabled` — `{ method, path, flag }`, emitted once per gated refusal
  ([[feature-flag-gating]]). Deliberately not routed to `server_error`.

This list covers only the signals verified while writing this page; it is not yet a complete
inventory of emitted events.

Verified against [[oauth-server-codebase]] at commit `2125ad0`.
