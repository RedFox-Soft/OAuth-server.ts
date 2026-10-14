---
type: concept
title: 'End-user pages and emails in English, Russian and Chinese'
tags: [architecture, contract, gotcha, accessibility, security]
sources: [oauth-server-codebase]
created: 2026-10-14
updated: 2026-10-14
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:interaction-page-families
    - predicate: relates_to
      object: concept:end-user-colour-scheme
    - predicate: relates_to
      object: concept:cookie-path-scoping
    - predicate: relates_to
      object: concept:consent-screen-decisions
---

# End-user pages and emails in English, Russian and Chinese

Since spec 097 every page an end user sees, and every end-user email, is written in English, Russian or
Simplified Chinese (`en`, `ru`, `zh-Hans`). The console, administrator emails and every protocol answer stay
English.

## How the language is chosen

The signals, in order, as the owner set them:

1. the person's explicit choice, a `_lang` cookie set by the switch;
2. the application's `ui_locales` (query, request object or pushed request — all merged into the stored
   parameters before the interaction is built);
3. the account's stored locale: `profile.locale`, else `claims.locale` (where an upstream provider's `locale`
   lands, `lib/federation/consts.ts` `COPIED_CLAIMS`);
4. the browser's `Accept-Language`, by q-value;
5. English.

Matching is RFC 4647 Lookup (`lib/i18n/languages.ts` `lookup`). Chinese is compared by **script**, after
`Intl.Locale#maximize`: `zh`, `zh-CN`, `zh-SG` are Simplified, `zh-TW` and `zh-HK` are Traditional and match
nothing, so a Traditional reader gets English rather than the wrong script. An unsupported or malformed value
is no match, never an error (OIDC Core §3.1.2.1). Every parser is bounded (1024 characters, 32 ranges).

**A sign-in decides once.** `lib/actions/authorization/interactions.ts` `interactionLanguage` resolves when the
interaction is created and stores `language` and `alternative` on it; a follow-up interaction of the same
authorization (consent after the password) copies them from the one that just finished, as `parJti` is copied.
So the stored locale only decides when a session already names the account; on the sign-in page itself the
account is unknown, and resolving again after the password would change the page language between two steps.
Every `ui/:uid/*` page reads `languageOf(interaction)` (`lib/interactions/index.ts`).

Pages outside a sign-in resolve per request with what they have (`lib/i18n/request.ts`): logout adds its own
`ui_locales`; the connected-apps page adds the person's stored locale; the pages behind an email link add the
language **the email was written in**, stored on the challenge record (`VerificationChallenge.language`,
`PasswordResetChallenge.language`), so the page matches the email even on another device. Device and sign-out
pages do not load the account only to choose a language.

## The switch, and why there is no menu

The owner's decision: the only control is one button under the card that switches between English and the
visitor's own language, and it is shown **only** when some signal names a non-English language
(`alternative`). `alternative` is the first non-English match over all signals, not the page language — so a
person whose account says `en` and whose browser says Russian still sees "Русский", and nobody is locked into
English by their own earlier choice.

It is a form of its own posting to `POST /ui/:uid/language` (`lib/interactions/languageSwitch.tsx`). Inside the
`ui` app, so the interaction cookie guard is its CSRF defence, as for every other form there. `lang` must be
`en` or exactly `alternative`, `page` must be in `SWITCH_PAGES`; anything else changes nothing and the redirect
is built from the uid and that closed list only. Pages outside a sign-in show no switch: they have no return
target that is not a URL taken from the request.

`_lang` is **not** partitioned by bucket, unlike the session cookie: the choice belongs to the person reading,
not to an identity, so it is one host-only cookie at `/` (`lib/i18n/cookie.ts`, one derivation —
[[cookie-path-scoping]]).

At sign-in completion (`lib/actions/authorization/resume.ts`, right after `loginAccount`) an explicit choice is
written to `profile.locale` by `recordOwnLanguage` in `lib/end_users/service.ts`. Never for a
directory-provisioned account (the directory owns `locale`), never when the stored value already means that
language (`ru-RU` stays), and never from `Accept-Language`. No audit record: it changes nobody's access.

## Catalogues

`lib/i18n/texts/<surface>/{en,ru,zh-Hans}.ts`, one file per language so a translation review is one diff. An
entry is a whole sentence with `{slots}`, or a plural object keyed by CLDR categories. Two rules a change must
keep:

- **Values are never templates.** `lib/i18n/message.tsx` splits only the catalogue's template; an application
  calling itself `{app}`, `<b>` or U+202E is shown literally, inside `<bdi>`.
- **An object with an `other` key is a plural.** A group of ordinary texts must not use `other` as a key (the
  consent group was renamed `undescribed` for this).

`test/i18n/catalogues.spec.ts` enumerates the directories on disk and holds every language to English: same
keys, same slot set, exactly the plural categories `Intl.PluralRules` reports for the language, nothing empty.
A dropped `{app}` would hide which application is asking.

Dates, lists and relative times are formatted on the server with an explicit locale (`lib/i18n/format.ts`):
Bun's default locale is always `en-US`, and a hydrated page that formatted again in the browser would rewrite
its own text. English dates use `en-GB` to keep the day-month order the consent page always had.

## Hydration and antd

The hydrated pages carry `language` in their props; `clientRoot.tsx` hands it to `EndUserTheme`, which sets
antd's `ConfigProvider locale` (so "Copy" becomes «Копировать») and provides `LanguageContext` to every
component. Server and client therefore render the same words; `test/dark_theme/hydration.spec.ts` checks every
hydrated page in every language. Decorative input icons carry `aria-hidden`, since antd names them in English.

## What stays English

`error`, `error_description`, `error_uri`, every JSON body, discovery values and scope identifiers
(RFC 6749 §4.1.2.1 keeps the description ASCII). The error page translates its own heading and explanation and
shows the code and description under `lang="en"`. `test/i18n/protocol_unchanged.spec.ts` sends protocol
requests with and without every language signal and requires identical answers.

## Headers and discovery

`htmlResponse` (`lib/html/csp.ts`) takes `language` and sets `Content-Language` and `Vary: Accept-Language,
Cookie`. End-user emails set `Content-Language` and `lang` on the HTML root. Both discovery documents of every
issuer publish `ui_locales_supported: ["en", "ru", "zh-Hans"]` — a fact of the build in
`lib/configs/application.ts`, not a setting.

## Not done, on purpose

No per-bucket or global default language (the owner's decision; a bucket default would slot in before English
without changing the order). No operator text overrides — issue #71. No language-tagged client metadata
(`client_name#ru`): application and operator text is shown as stored. The Chinese catalogue was written without
native review.
