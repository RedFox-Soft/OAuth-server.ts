/*
 * Sign-in in front of a web app, through the operator's proxy (specs/122). Import-free, so the client resolver,
 * the bucket resolver and the check can all read these without reaching each other.
 */

/*
 * The prefix of the built-in client each end-user bucket signs people in to its apps behind a proxy through.
 * A `.` is outside the alphabet every generated client id is drawn from, as with the account page's
 * `account.`; registration refuses it too, for a deployment whose id factory is its own.
 */
export const BEHIND_PROXY_CLIENT_PREFIX = 'proxy.';

/* The reserved path on the app's own host the sign-in returns to; the proxy relays it to the check. */
export const BEHIND_PROXY_CALLBACK_PATH = '/_foxauth/callback';

/*
 * The check a proxy makes, beneath the project's own address (`/verify` bare is the default bucket's). Every method
 * is answered: the method of the check is not significant, the original one is read from `X-Forwarded-Method`.
 */
export const BEHIND_PROXY_CHECK_BASE = '/verify';
export const BEHIND_PROXY_CHECK_ROUTE = `${BEHIND_PROXY_CHECK_BASE}/:appId`;

/*
 * The check a proxy makes for an API whose tokens it checks (specs/123), one level deeper than an app's so no app id
 * can ever name an API, and the protected-resource metadata the project serves for that API.
 */
export const BEHIND_PROXY_API_CHECK_ROUTE = `${BEHIND_PROXY_CHECK_BASE}/api/:checkId`;
export const BEHIND_PROXY_API_METADATA_ROUTE = `${BEHIND_PROXY_API_CHECK_ROUTE}/metadata`;
