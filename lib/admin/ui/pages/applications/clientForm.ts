/*
 * An application's settings as the console edits them: the field lists, the shape the server sends, the shape the
 * form holds, and the two translations between them. Kept free of React so the page, the Settings tab and the
 * situation chooser share one reading of what a form means.
 */

export const GRANT_OPTIONS = [
	{ label: 'authorization_code', value: 'authorization_code' },
	{ label: 'refresh_token', value: 'refresh_token' },
	{ label: 'client_credentials', value: 'client_credentials' },
	{
		label: 'device_code',
		value: 'urn:ietf:params:oauth:grant-type:device_code'
	},
	{ label: 'ciba', value: 'urn:openid:params:grant-type:ciba' }
];
export const AUTH_OPTIONS = [
	{ label: 'none (public / PKCE)', value: 'none' },
	{ label: 'client_secret_basic', value: 'client_secret_basic' },
	{ label: 'client_secret_post', value: 'client_secret_post' },
	{ label: 'client_secret_jwt', value: 'client_secret_jwt' },
	{ label: 'private_key_jwt (key set below)', value: 'private_key_jwt' }
];

/*
 * The key and request-protection attributes, as text fields and switches. Algorithms are free text:
 * the set a deployment supports is the server's to check, and a picker here would be a second copy
 * of it. An emptied text field on an edit removes the attribute.
 */
export const KEY_TEXT_FIELDS = [
	['jwksUri', 'Key set URL (jwks_uri)', 'https://app.example.com/jwks'],
	['tokenEndpointAuthSigningAlg', 'Client assertion signing alg', 'PS256'],
	['idTokenSignedResponseAlg', 'ID Token signing alg', 'RS256'],
	['authorizationSignedResponseAlg', 'JARM signing alg', 'PS256'],
	['requestObjectSigningAlg', 'Request Object signing alg', 'PS256'],
	[
		'backchannelLogoutUri',
		'Back-channel logout URI',
		'https://app.example.com/logout'
	],
	[
		'sectorIdentifierUri',
		'Sector identifier URI (pairwise)',
		'https://app.example.com/sector.json'
	]
] as const;
export const KEY_SWITCHES = [
	['requirePushedAuthorizationRequests', 'Require pushed authorization (PAR)'],
	['dpopBoundAccessTokens', 'Require DPoP-bound access tokens'],
	['requireSignedRequestObject', 'Require signed Request Objects'],
	['backchannelLogoutSessionRequired', 'Send sid in logout tokens']
] as const;
type KeyTextField = (typeof KEY_TEXT_FIELDS)[number][0];
type KeySwitch = (typeof KEY_SWITCHES)[number][0];
export type KeyAttributes = { [K in KeyTextField]?: string } & {
	[K in KeySwitch]?: boolean;
} & { subjectType?: 'public' | 'pairwise'; jwks?: unknown };

export function parseJwks(text: string | undefined): unknown {
	const trimmed = text?.trim();
	if (!trimmed) return undefined;
	const value: unknown = JSON.parse(trimmed);
	if (typeof value !== 'object' || value === null || !('keys' in value)) {
		throw new TypeError('a key set is a JSON object with a "keys" array');
	}
	return value;
}

export const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
// Mirrors the request schema's union, which is the server's real answer on what it will accept.
export const CIBA_DELIVERY_MODE_OPTIONS = [
	{ label: 'poll', value: 'poll' },
	{ label: 'ping', value: 'ping' }
];

/* When an application first and last received a token (spec 107); null until it has. */
export interface LastUsed {
	firstUsedAt: number;
	lastUsedAt: number;
}

/* What an application needs to be configured, as the server states it (lib/admin/clients/connection.ts). */
export interface Connection {
	issuer: string | null;
	discoveryUrl: string | null;
	clientId: string;
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	endpoints: Record<string, string>;
	signInPageUrl: string | null;
	lastUsed: LastUsed | null;
}

export interface ClientView {
	clientId: string;
	projectId?: string;
	clientName?: string;
	applicationType: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris: string[];
	postLogoutRedirectUris?: string[];
	scope?: string;
	requireConsent: boolean;
	partialConsent?: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping';
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
	registeredDynamically?: boolean;
	hasLogo?: boolean;
	logo?: string;
	hasSecret?: boolean;
	lastUsed?: LastUsed | null;
	connection?: Connection;
	primaryColor?: string;
	policyUri?: string;
	tosUri?: string;
	corsOrigins?: string[];
}
export type ClientRow = ClientView & KeyAttributes;

export interface FormValues extends Omit<KeyAttributes, 'jwks'> {
	jwksText?: string;
	clientName?: string;
	applicationType: 'web' | 'native';
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris?: string;
	postLogoutRedirectUris?: string;
	scope?: string;
	requireConsent: boolean;
	partialConsent?: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping';
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
	logo?: string | null;
	primaryColor?: string | null;
	policyUri?: string;
	tosUri?: string;
	corsOrigins?: string[];
}

export const DEFAULT_VALUES: FormValues = {
	applicationType: 'web',
	grantTypes: ['authorization_code'],
	tokenEndpointAuthMethod: 'none',
	requireConsent: true
};

function lines(text: string | undefined): string[] {
	return (text ?? '')
		.split('\n')
		.map((s) => s.trim())
		.filter(Boolean);
}

/* The form's reading of a stored application. The logo is read separately: the list carries only whether there is one. */
export function formValuesOf(row: ClientRow): FormValues {
	return {
		clientName: row.clientName,
		// The server stores one of the two; any other value would have been refused on the way in.
		applicationType: row.applicationType as 'web' | 'native',
		grantTypes: row.grantTypes,
		tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
		redirectUris: row.redirectUris.join('\n'),
		postLogoutRedirectUris: (row.postLogoutRedirectUris ?? []).join('\n'),
		scope: row.scope,
		requireConsent: row.requireConsent,
		partialConsent: row.partialConsent ?? false,
		authorizationDetailsTypes: row.authorizationDetailsTypes,
		backchannelTokenDeliveryMode: row.backchannelTokenDeliveryMode,
		backchannelClientNotificationEndpoint:
			row.backchannelClientNotificationEndpoint,
		policyUri: row.policyUri ?? '',
		tosUri: row.tosUri ?? '',
		corsOrigins: row.corsOrigins ?? [],
		logo: row.logo ?? null,
		primaryColor: row.primaryColor ?? null,
		jwksText: row.jwks ? JSON.stringify(row.jwks, null, 2) : '',
		subjectType: row.subjectType,
		...Object.fromEntries(
			KEY_TEXT_FIELDS.map(([name]) => [name, row[name] ?? ''])
		),
		...Object.fromEntries(
			KEY_SWITCHES.map(([name]) => [name, row[name] ?? false])
		)
	};
}

/*
 * On create an attribute is sent only when set. On an edit every one is sent, an emptied text
 * field as null — which removes it — so what the form shows is what the client then holds.
 */
function keyAttributes(values: FormValues, editing: boolean) {
	const body: Record<string, unknown> = {};
	const jwks = parseJwks(values.jwksText);
	if (jwks !== undefined || editing) body.jwks = jwks ?? null;
	for (const [name] of KEY_TEXT_FIELDS) {
		const value = values[name]?.trim();
		if (value || editing) body[name] = value || null;
	}
	for (const [name] of KEY_SWITCHES) {
		if (values[name] || editing) body[name] = Boolean(values[name]);
	}
	if (values.subjectType) body.subjectType = values.subjectType;
	return body;
}

/* What the application held when the form opened, so an edit sends the logo and the colour only when they changed. */
export interface Stored {
	logo: string | null;
	primaryColor: string | null;
}

function presentation(values: FormValues, stored: Stored | null) {
	const editing = stored !== null;
	const body: Record<string, unknown> = {};
	for (const name of ['policyUri', 'tosUri'] as const) {
		const value = values[name]?.trim();
		if (value || editing) body[name] = value || null;
	}
	const logo = values.logo ?? null;
	if (editing ? logo !== stored.logo : logo) body.logo = logo;
	// Sent on an edit only when changed, so saving an unrelated field never writes the colour back.
	const colour = values.primaryColor ?? null;
	if (editing ? colour !== stored.primaryColor : colour) {
		body.primaryColor = colour;
	}
	return body;
}

/* The request body for a create (`stored` null) or an edit of an application with `stored` presentation. */
export function buildBody(values: FormValues, stored: Stored | null = null) {
	const editing = stored !== null;
	return {
		...keyAttributes(values, editing),
		...presentation(values, stored),
		clientName: values.clientName,
		applicationType: values.applicationType,
		grantTypes: values.grantTypes,
		tokenEndpointAuthMethod: values.tokenEndpointAuthMethod,
		redirectUris: lines(values.redirectUris),
		postLogoutRedirectUris: lines(values.postLogoutRedirectUris),
		scope: values.scope,
		requireConsent: values.requireConsent,
		partialConsent: Boolean(values.partialConsent),
		corsOrigins: values.corsOrigins ?? [],
		...(values.authorizationDetailsTypes?.length
			? { authorizationDetailsTypes: values.authorizationDetailsTypes }
			: {}),
		...(values.backchannelTokenDeliveryMode
			? {
					backchannelTokenDeliveryMode: values.backchannelTokenDeliveryMode
				}
			: {}),
		...(values.backchannelClientNotificationEndpoint
			? {
					backchannelClientNotificationEndpoint:
						values.backchannelClientNotificationEndpoint
				}
			: {})
	};
}
