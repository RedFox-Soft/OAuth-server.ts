---
type: concept
title: 'prompt=create: opening a sign-in on account creation'
tags: [architecture, contract, oidc]
sources: [oauth-server-codebase]
created: 2026-10-20
updated: 2026-10-20
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:admin-console-signin
    - predicate: relates_to
      object: concept:interaction-page-families
    - predicate: relates_to
      object: concept:end-user-onboarding
---

# prompt=create: opening a sign-in on account creation

The server accepts `prompt=create` from Initiating User Registration via OpenID Connect 1.0 (Final,
December 2022). A client sends it when its user should see account creation rather than sign-in. It was
added on 2026-10-20 because the site's "Create a free account" button had no way to open the cloud
console on its registration page: it opened `/admin`, which showed a password form for an account the
newcomer did not have, with registration as a small link under it.

## Where it lives

- **Accepted** by `supportedPrompts()` (`lib/addon/interactions.ts`) while the policy has a `login`
  prompt. `create` is not a prompt of its own: the login prompt carries it, as the check with reason
  `create_prompt` (`lib/helpers/interaction_policy/prompts/login.ts`). The two names live in
  `lib/consts/prompt_create.ts`.
- **The check fires until a sign-in result exists** (`!oidc.result?.login`). So `create` opens an
  interaction even for somebody already signed in, the way `prompt=login` does. And it cannot loop: the
  new account's sign-in at the end of the interaction satisfies it.
- **The interaction opens on `/ui/:uid/registration`** instead of `/login` when the login prompt failed for
  `create_prompt` (`lib/actions/authorization/interactions.ts`). Nothing else about the interaction
  differs. Registration then sends the person to sign in within the same interaction, as before, and that
  sign-in returns them to the client with a code.
- **Discovery publishes `prompt_values_supported`**, read from the same `supportedPrompts()`. §4.1 says a
  provider that supports `create` MUST publish the member and list every value it accepts. The value is
  handed into `calculateDiscovery` by `lib/actions/discovery.ts`, so the configuration layer does not
  import the behaviour layer. It is classified `oidc` in `metadataClassification`: the spec that
  registered it is an OpenID one, so the RFC 8414 document leaves it out.

## A project that takes no sign-ups

The specification does not say what happens when the provider supports `create` but will not create an
account for this request. Here, the registration page's GET redirects to the sign-in page of the same
interaction (`lib/interactions/index.ts`) when the request asked for `create` and either:

- the project is closed to sign-ups, or paused by its plan;
- or password sign-in is off.

The application asked for account creation without being able to know the project's settings. Its user
is better served by completing the same authorization another way than by the "registration closed"
dead end. A request that did not ask for `create` still gets the 403 page, as before.

## The console's sign-up address

`GET /admin/signup` starts the console's sign-in leg exactly like `/admin/login`, with `prompt=create`
added (`startSignIn` in `lib/admin/auth/login.ts`); see [[admin-console-signin]]. It is in `safeNext`'s
list of non-pages (`lib/admin/auth/next.ts`). The site's `CLOUD_SIGN_UP` (`website/src/data/cloud.ts`)
points at it.

Tests: `test/prompt_create/prompt_create.spec.ts` (client audience) and
`test/admin/admin_registration.spec.ts` (the console address).
