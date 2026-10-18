/*
 * FoxAuth Cloud, the instance we run at auth.foxauth.dev. Its console is where a new account is created: the
 * sign-in page there offers "Register now!", and a new administrator gets a personal team and Free projects.
 *
 * The Free plan's limits are written in the pricing messages rather than computed, because they are the
 * production instance's plan catalogue, not this repository's defaults. Checked against production on
 * 2026-10-18 (plan `free`: 1,000,000 monthly active users, raised from 100,000 that day; 2 projects per
 * administrator, 10 applications and 10 APIs per project, no enterprise sign-in, custom slug or custom domain).
 */
export const CLOUD_SIGN_UP = 'https://auth.foxauth.dev/admin';

/*
 * The flags switched on at auth.foxauth.dev, so the Features page can mark the cards a cloud project gets. Not read
 * from production at build time — the site builds without credentials — so it is checked by hand: last read from
 * production's settings on 2026-10-16, after clientCredentials, revocation, introspection, backchannelLogout,
 * deviceFlow, clientIdMetadataDocument, dpop and par were switched on. Change this when production changes.
 * Operator-only switches (the error store, Sentry) are left out: a tenant never sees them.
 */
export const CLOUD_FLAGS_ON: ReadonlySet<string> = new Set([
	'federation.enabled',
	'mcp.enabled',
	'plans.enabled',
	'resourceIndicators.enabled',
	'rpInitiatedLogout.enabled',
	'clientCredentials.enabled',
	'revocation.enabled',
	'introspection.enabled',
	'backchannelLogout.enabled',
	'deviceFlow.enabled',
	'clientIdMetadataDocument.enabled',
	'dpop.enabled',
	'par.enabled',
	'cors.enabled',
	'rateLimit.enabled'
]);
