/*
 * Everything a daily usage report may carry (specs/113), declared once.
 *
 * The report builder emits only what is declared here, the console explains these entries, and the site
 * page is generated from them, so what an operator reads and what leaves their server cannot drift apart.
 *
 * Import-free, like every lib/consts/ declaration: the docs export and the site read it without loading the
 * server.
 */

/*
 * FoxTrust spec 034 declares this path permanent. It is compiled into every release and has no override,
 * by owner decision (2026-10-28): an instance that never upgrades keeps sending here, so the receiver may
 * never move it.
 */
export const TELEMETRY_DESTINATION =
	'https://api.foxtrust.dev/v1/foxauth/usage';

/* A change to a field's meaning or a range boundary is a new format, never an edit of this one. */
export const REPORT_FORMAT = 1;

/*
 * Every count is sent as one of these bands, never as a number: coarse enough that a report does not
 * reveal a business's volume, fine enough to tell a trial from a production deployment.
 */
export const RANGE_LABELS = [
	'0',
	'1',
	'2-10',
	'11-100',
	'101-1000',
	'1001-10000',
	'10001-100000',
	'100001+'
] as const;

export type RangeLabel = (typeof RANGE_LABELS)[number];

/*
 * Grant types are reported under short names so that no URN becomes a document key in the counters, and
 * the receiver gets a closed vocabulary. The two JWT assertion grants are one family to a maintainer.
 */
export const GRANT_SHORT_NAMES: Readonly<Record<string, string>> = {
	authorization_code: 'authorization_code',
	client_credentials: 'client_credentials',
	refresh_token: 'refresh_token',
	'urn:ietf:params:oauth:grant-type:device_code': 'device_code',
	'urn:openid:params:grant-type:ciba': 'ciba',
	'urn:ietf:params:oauth:grant-type:jwt-bearer': 'jwt_bearer',
	'urn:ietf:params:oauth:grant-type:jwt-dpop': 'jwt_bearer',
	'urn:ietf:params:oauth:grant-type:token-exchange': 'token_exchange'
};

/*
 * The boolean settings whose on/off a report carries. A boolean setting is either here or in
 * UNREPORTED_SETTINGS with a reason; test/telemetry/declaration.spec.ts fails on one that is in neither.
 */
export const REPORTED_SETTINGS: readonly string[] = [
	'authorization.allowOmittingSingleRegisteredRedirectUri',
	'pkce.required',
	'par.enabled',
	'par.allowUnregisteredRedirectUris',
	'dpop.enabled',
	'dpop.requireNonce',
	'introspection.enabled',
	'jwtIntrospection.enabled',
	'responseMode.jwt.enabled',
	'fapi.enabled',
	'ipsieSl1.enabled',
	'clientAuth.issuerOnlyAudience',
	'clientCredentials.enabled',
	'tokenExchange.enabled',
	'jwtBearer.enabled',
	'backchannelLogout.enabled',
	'encryption.enabled',
	'userinfo.enabled',
	'jwtUserinfo.enabled',
	'revocation.enabled',
	'globalTokenRevocation.enabled',
	'rpInitiatedLogout.enabled',
	'claimsParameter.enabled',
	'mTLS.enabled',
	'mTLS.certificateBoundAccessTokens',
	'mTLS.selfSignedTlsClientAuth',
	'mTLS.tlsClientAuth',
	'deviceFlow.enabled',
	'ciba.enabled',
	'plans.enabled',
	'requestObjects.enabled',
	'requestObjects.requireSignedRequestObject',
	'resourceIndicators.enabled',
	'richAuthorizationRequests.enabled',
	'cors.enabled',
	'rateLimit.enabled',
	'federation.enabled',
	'mcp.enabled',
	'scim.enabled',
	'scim.secretCredentials',
	'scim.staticTokens',
	'scim.strict',
	'errorStore.enabled',
	'sentry.enabled',
	'registration.enabled',
	'registration.issueRegistrationAccessToken',
	'clientIdMetadataDocument.enabled',
	'registrationManagement.enabled',
	'registrationManagement.rotateRegistrationAccessToken',
	'conformIdTokenClaims'
];

export const UNREPORTED_SETTINGS: Readonly<Record<string, string>> = {
	'telemetry.enabled':
		'a report exists only while it is on, so it would always read true',
	'mTLS.trustProxyCertificateHeader':
		"describes the deployment's proxy in front of the server, not a feature anyone adopts",
	'rateLimit.trustedProxy':
		"describes the deployment's proxy in front of the server, not a feature anyone adopts"
};

export interface ReportField {
	readonly path: string;
	readonly meaning: string;
	readonly values: string;
	/* When the field may be absent from a report, and why; undefined when it is always present. */
	readonly absentWhen?: string;
}

const RANGES = `one of ${RANGE_LABELS.join(', ')}`;

export const REPORT_FIELDS: readonly ReportField[] = [
	{
		path: 'format',
		meaning: 'The version of this report format.',
		values: '1'
	},
	{
		path: 'instanceId',
		meaning:
			'A random identifier this server generated for itself and keeps in its database. It is derived from nothing, so it says nothing about who runs the server; it only lets reports from one server be grouped.',
		values: 'a UUID'
	},
	{
		path: 'foxauth.version',
		meaning: 'The FoxAuth release this server runs.',
		values: 'a version such as 1.3.0',
		absentWhen: 'the package manifest cannot be read'
	},
	{
		path: 'runtime.bun',
		meaning: 'The Bun version this server runs on.',
		values: 'a version such as 1.3.4'
	},
	{
		path: 'runtime.os',
		meaning: 'The operating system.',
		values: 'a Node.js platform name such as linux, darwin or win32'
	},
	{
		path: 'runtime.arch',
		meaning: 'The processor architecture.',
		values: 'a Node.js architecture name such as x64 or arm64'
	},
	{
		path: 'runtime.container',
		meaning:
			'Whether the server appears to run in a container. A best guess from the usual container markers.',
		values: 'true or false'
	},
	{
		path: 'storage',
		meaning: 'Which database the server stores its data in.',
		values: 'mongodb or postgres'
	},
	{
		path: 'features.<setting>',
		meaning:
			'Whether a feature setting is on. Only the on/off of the settings listed as reported is sent, never a value.',
		values: 'true or false'
	},
	{
		path: 'size.projects',
		meaning:
			"How many projects the server holds, the administrators' own project included.",
		values: RANGES
	},
	{
		path: 'size.applications',
		meaning: 'How many applications are registered across all projects.',
		values: RANGES
	},
	{
		path: 'size.apis',
		meaning: 'How many APIs (protected resources) are declared.',
		values: RANGES
	},
	{
		path: 'size.administrators',
		meaning: 'How many administrator accounts exist.',
		values: RANGES
	},
	{
		path: 'size.monthlyActiveUsers',
		meaning:
			'People who received tokens this calendar month, summed over projects.',
		values: RANGES
	},
	{
		path: 'day.date',
		meaning:
			'The UTC day the day figures below describe: the day before the report.',
		values: 'a date, YYYY-MM-DD',
		absentWhen:
			'the server has no figures for that day yet, for example on its first day'
	},
	{
		path: 'day.tokens.<grant>',
		meaning:
			'How many token responses that grant type produced that day. A grant type with none is left out.',
		values: `${RANGES}; grant names are ${[...new Set(Object.values(GRANT_SHORT_NAMES))].join(', ')}`,
		absentWhen: 'the server has no figures for that day yet'
	},
	{
		path: 'day.serverErrors',
		meaning:
			'Defects the server recorded that day: 5xx responses and faults in background work, counted whether or not its error store is on.',
		values: RANGES,
		absentWhen: 'the server has no figures for that day yet'
	}
];

/*
 * What the receiver refuses (FoxTrust spec 034, research R5). A report that breaks one is answered 422 and
 * lost, so the declaration above is held to them by test/telemetry/declaration.spec.ts rather than left to
 * be discovered in production.
 */
export const RECEIVER_KEY_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const RECEIVER_MAX_FEATURES = 100;
export const RECEIVER_MAX_TOKEN_KEYS = 32;

/* SC-006: a report stays small; FoxTrust refuses anything over 16 KiB. */
export const REPORT_MAX_BYTES = 4096;
