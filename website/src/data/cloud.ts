/*
 * FoxAuth Cloud, the instance we run at auth.foxauth.dev. Its console is where a new account is created: the
 * sign-in page there offers "Register now!", and a new administrator gets a personal team and Free projects.
 *
 * The Free plan's limits are written in the pricing messages rather than computed, because they are the
 * production instance's plan catalogue, not this repository's defaults. Since 2026-11-17 the cloud is free during
 * the beta, read back from production that day (plan `free`: no limit on monthly active users, applications, APIs
 * or connected services; 10 projects per administrator; enterprise sign-in and custom slug on, custom domain off,
 * set up on request).
 */
export const CLOUD_SIGN_UP = 'https://auth.foxauth.dev/admin/signup';

/*
 * Every link to the sign-up carries this. A crawler cannot register, and the page behind the link is a sign-in
 * form with nothing to rank, so there is no reason to send it there from every page of the site.
 */
export const CLOUD_SIGN_UP_REL = 'nofollow';

/*
 * The flags switched on at auth.foxauth.dev, so the Features page can mark the cards a cloud project gets. Not read
 * from production at build time — the site builds without credentials — so it is checked by hand: last read from
 * production's settings on 2026-10-16, after clientCredentials, revocation, introspection, backchannelLogout,
 * deviceFlow, clientIdMetadataDocument, dpop and par were switched on. Re-checked on 2026-11-04 against what
 * production's discovery document and /mcp metadata show (registration, CIBA, the JWT bearer grant, RAR and ID-JAG
 * off); the switches discovery does not reveal (federation, SCIM, plans) were not re-read. On 2026-11-10 FoxTrust's
 * attacker list was switched on beside attack reporting, read back from production's settings. On 2026-11-17 the
 * whole settings list was read back from production: network facts were switched on that day, and
 * clientAuth.issuerOnlyAudience is on by its 2.0.0 default. Change this when production changes.
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
	'rateLimit.enabled',
	'attackReports.enabled',
	'attackerList.enabled',
	'networkFacts.enabled',
	'clientAuth.issuerOnlyAudience'
]);

/*
 * The plan features the Free plan includes, so the guide can mark an answer "Not on the Free plan". Free has
 * enterprise sign-in and a custom slug, not a custom domain (read back from production on 2026-11-17, as above).
 * Change this when the Free plan changes.
 */
export const CLOUD_FREE_FEATURES: ReadonlySet<string> = new Set<string>([
	'enterpriseSignIn',
	'customSlug'
]);

/*
 * Where a request for a paid plan goes, and the subject the team's inbox sorts it by: the guide's "Ask for a paid
 * plan" writes this mail. The subject stays English in every language.
 */
export const WAITLIST_ADDRESS = 'hello@foxauth.dev';
export const WAITLIST_SUBJECT = 'FoxAuth Cloud paid plans waitlist';

/*
 * The pricing page's Enterprise request goes through Web3Forms, which mails it to the owner's inbox: the site is
 * static and sends no mail itself. The access key is public by design (it only lets a form post to the inbox it was
 * issued for), so it lives here rather than in a build variable. The subject stays English in every language.
 */
export const ENTERPRISE_FORM_KEY = '754f57f5-de46-4422-a0cb-7664bf782aed';
export const ENTERPRISE_SUBJECT = 'FoxAuth Enterprise request';

/* The console of FoxAuth Cloud: what a prompt names, and where the guide's buttons lead. */
export const CLOUD_CONSOLE = 'https://auth.foxauth.dev/admin';
