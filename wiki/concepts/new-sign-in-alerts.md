---
type: concept
title: "An email about a sign-in from a new network or browser"
tags: [architecture, contract, security, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-18
updated: 2026-11-18
---

# An email about a sign-in from a new network or browser

Spec 138. When an account signs in from a network or a browser it has not used in 90 days, its owner is emailed
where and how, with one link, **This wasn't me**, that signs the account out everywhere. For the administrators of the
instance it is on by default; for a project's people, a project setting turns it on. It exists because the sign-in
log of [[person-activity]] only helps someone who reads it.

## Decided in the flush, sent after the write

- `alertsFor` (`lib/sign_in_alerts/alerts.ts:103`) runs in `flushOnce` between `withLookups` and the write
  (`lib/person_activity/flush.ts:74`): the network owner exists only after the lookup of [[address-lookup]], and no
  request waits on a flush. It marks the row it will email about (`alerted`: `network`, `browser`, `both`), so the
  mark is written with the row and needs no second write.
- `sendAlerts` (`alerts.ts:209`) runs only after a write with no failed chunk (`flush.ts:88`): an email about a
  sign-in the log does not hold could not be checked. A failed delivery is logged and never retried; the row keeps
  the mark of the decision.
- **Consequence**: with `personActivity.enabled` off there are no rows and so no emails; the setting's description
  says so.

## What "new" means

`judge` (`lib/sign_in_alerts/judge.ts:57`) compares a successful sign-in with the account's successful sign-ins of the
last 90 days (`listForPerson`, limit 500, plus earlier rows of the same flush) that came **before** it:

- **Network**: the AS number when both sides know one; else the country when both know one; else not judged. Comparing
  only at a level both sides know keeps a server that turned lookups on yesterday from calling every network new.
- **Browser**: browser and system family when both sides know a device.
- **Not new**: another address inside a known network (home and mobile addresses change all the time).
- **Nothing to compare**: no email. A dormant account's next sign-in therefore sends none; the row is still kept.

## Who is emailed, and how often

- Only an active account (`canSignIn`) with a verified address, only while mail is configured, only where
  `alertsOn(bucket)` (`lib/sign_in_alerts/setting.ts`): `newSignInAlerts ?? (bucket._id === ADMIN_BUCKET_ID)`. The
  field is absent by default, so no project record is rewritten. **Gotcha**: creating a project drops the field;
  it is set by the project PATCH, as the console does.
- `claim` (`lib/sign_in_alerts/claim.ts:21`): two insert-if-absent claims in `SignInAlertClaim` (account-owned,
  two days): the account, day, network and browser, then one of five daily slots. Two processes flushing the same
  sign-ins email once. The claims go with every sign-out everywhere, which resets the day's count; that is right
  after the account's access was just reset.

## The email

`lib/mail/templates/new_sign_in.ts`, texts `EMAIL_TEXTS[language].newSignIn` in three languages, language
`emailLanguage(user)`. One fact a line: when (UTC), the application, how, the browser on the system (the account
page's tables, moved to `lib/person_activity/sign_in_words.ts`), city, region and country, and the network owner. Never
the address, as the person's own Recent sign-ins page ([[connected-apps-page]]). The administrators' project is called
"the FoxAuth console".

## This wasn't me

- The link is spec 126's link store with purpose `notme` and `signInId` (`lib/sign_in_alerts/link.ts:23`): a digest
  stored, 72 hours, spent once by `consume`; `followLink` and `readDisownLink` refuse it, and the not-me page refuses
  every other purpose ([[totp-second-factor]]).
- `GET/POST /account/not-me` (`lib/account_page/not_me_routes.ts`), plain page family. Opening shows what will happen;
  only the POST acts (a mail scanner changes nothing). `acceptsAt` (`:51`): a link acts only where its own project's
  pages are served (`accountPageBase` equal), so the administrators' links and those of a project without an address
  work at the instance's root and nowhere else, and a project's own address accepts only its links.
- A person: `signOutOwnAccount` with `enduser.signout` by the person (self-service), then the reset email when they have
  a password and the project offers self-service reset, else the page says where to change it.
- An administrator: `admin.signout` recorded as the administrator themself, `signOutAdministrator`, then every other
  active super administrator is emailed who, when and from where (`lib/sign_in_alerts/report.ts`, English). No reset
  email: administrators have no self-service reset, so the page says to ask a super administrator. A path under
  `/admin/` was rejected because the console shell and its sign-in redirect own that prefix.
- Never locks, deactivates or removes a factor.

## Fence

`2026-11-18-new-sign-in-alerts-fence`: an older release knows neither `alerted`, the `notme` purpose nor the claim
area, and would stop emailing without saying so.
