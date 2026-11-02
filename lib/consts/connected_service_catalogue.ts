/*
 * The services a project can let its people connect by name (specs/117 R4), and everything about each that is
 * the same for every deployment.
 *
 * DATA, NOT BEHAVIOUR, as lib/consts/known_providers.ts is for sign-in: each field states one way a provider
 * differs from the others, so a connect flow reads the difference instead of branching on the provider's name
 * (Principle II). The differences are real: Slack hands the person's token back under `authed_user`, takes the
 * scopes it is asked for in `user_scope` joined by commas, and treats a code challenge as making the app public;
 * GitHub answers with comma-separated scopes; Microsoft's `sub` is pairwise per application while `oid` is the
 * person within a directory; Slack's user ids are unique only within a workspace.
 *
 * Endpoints and issuers that the sign-in catalogue already states are read from it, never written twice.
 *
 * Apple is absent on purpose: it issues no token any Apple service API accepts, so there is nothing to connect.
 * Slack is present here only; it is not a sign-in provider.
 *
 * Import-free beyond the sign-in catalogue, which is itself import-free: the console bundles this module.
 */
import { knownProvider } from './known_providers.js';

/*
 * A dotted path into a JSON document; `a|b` takes the first that is present. Several paths are joined with `:`
 * into one key, for a provider whose account is unique only together with its workspace or directory.
 */
export type IdentityPaths = readonly string[];

export type CatalogueIdentity =
	| {
			/* From the verified ID token. */
			readonly source: 'id_token';
			readonly idPaths: IdentityPaths;
			readonly labelPath: string;
	  }
	| {
			readonly source: 'endpoint';
			readonly url: string;
			readonly idPaths: IdentityPaths;
			readonly labelPath: string;
	  }
	| {
			/* From the token endpoint's own answer. */
			readonly source: 'token';
			readonly idPaths: IdentityPaths;
			readonly labelPath: string;
	  };

export type Revocation =
	/* RFC 7009's shape: a form with `token` (and a hint), client authentication as at the token endpoint. */
	| {
			readonly kind: 'form';
			readonly url: string;
			readonly clientAuth: boolean;
	  }
	/* GitHub: DELETE the whole grant, Basic client authentication, the access token in a JSON body. */
	| { readonly kind: 'github_grant'; readonly urlTemplate: string }
	/* Slack: the token revokes itself. */
	| { readonly kind: 'slack'; readonly url: string }
	| { readonly kind: 'none' };

export type CatalogueProtocol =
	/* Endpoints from the issuer's discovery document; the issuer comes from the sign-in catalogue. */
	| { readonly kind: 'oidc'; readonly knownProviderId: 'google' | 'microsoft' }
	| {
			readonly kind: 'oauth2';
			readonly authorizationEndpoint: string;
			readonly tokenEndpoint: string;
			readonly tokenAuth: 'post' | 'basic';
	  };

export interface CatalogueValue {
	readonly name: 'clientId' | 'clientSecret' | 'tenant';
	readonly label: string;
	readonly secret: boolean;
	readonly hint: string;
}

export interface ConnectedServiceEntry {
	readonly catalogueId: 'google' | 'github' | 'slack' | 'microsoft';
	readonly displayName: string;
	readonly protocol: CatalogueProtocol;
	/* Added to every authorization request, for a long-lived token. */
	readonly extraAuthorizationParams: Readonly<Record<string, string>>;
	readonly scopeParam: 'scope' | 'user_scope';
	readonly scopeSeparator: ' ' | ',';
	readonly responseScopeSeparator: ' ' | ',';
	/* Always asked for, beside the administrator's scopes, because identity or refresh depends on them. */
	readonly alwaysScopes: readonly string[];
	/* What the console proposes for a new service. */
	readonly defaultScopes: readonly string[];
	/* Where the person's tokens sit in the token response, when not at its top level. */
	readonly tokenPath?: string;
	readonly pkce: 'S256' | 'never';
	readonly identity: CatalogueIdentity;
	readonly revocation: Revocation;
	/* Where a person removes this application's access themselves, when revocation could not. */
	readonly manageAccessUrls: readonly string[];
	readonly requiredValues: readonly CatalogueValue[];
	readonly consoleUrl: string;
	readonly steps: readonly string[];
}

const CLIENT_ID: CatalogueValue = {
	name: 'clientId',
	label: 'Client ID',
	secret: false,
	hint: 'From the application you registered at the provider.'
};
const CLIENT_SECRET: CatalogueValue = {
	name: 'clientSecret',
	label: 'Client secret',
	secret: true,
	hint: 'Stored encrypted; never shown again.'
};

function oauth2Endpoints(catalogueId: 'github'): {
	authorizationEndpoint: string;
	tokenEndpoint: string;
} {
	const protocol = knownProvider(catalogueId)?.protocol;
	if (protocol?.kind !== 'profile_api') {
		throw new Error(
			`the sign-in catalogue no longer states ${catalogueId}'s endpoints`
		);
	}
	return {
		authorizationEndpoint: protocol.authorizationEndpoint,
		tokenEndpoint: protocol.tokenEndpoint
	};
}

const GOOGLE: ConnectedServiceEntry = {
	catalogueId: 'google',
	displayName: 'Google',
	protocol: { kind: 'oidc', knownProviderId: 'google' },
	/*
	 * `access_type=offline` is what yields a refresh token at all; `prompt=consent` makes Google issue one again on
	 * a reconnect, which it otherwise does only on the first consent.
	 */
	extraAuthorizationParams: { access_type: 'offline', prompt: 'consent' },
	scopeParam: 'scope',
	scopeSeparator: ' ',
	responseScopeSeparator: ' ',
	alwaysScopes: ['openid', 'email'],
	defaultScopes: [],
	pkce: 'S256',
	identity: { source: 'id_token', idPaths: ['sub'], labelPath: 'email' },
	/* Revoking either token revokes the whole grant. */
	revocation: {
		kind: 'form',
		url: 'https://oauth2.googleapis.com/revoke',
		clientAuth: false
	},
	manageAccessUrls: ['https://myaccount.google.com/permissions'],
	requiredValues: [CLIENT_ID, CLIENT_SECRET],
	consoleUrl: 'https://console.cloud.google.com/apis/credentials',
	steps: [
		'Create an OAuth client ID of type "Web application".',
		'Add the callback address below as an authorised redirect URI.',
		'Enable the APIs your agents will call and list their scopes here.'
	]
};

const GITHUB: ConnectedServiceEntry = {
	catalogueId: 'github',
	displayName: 'GitHub',
	protocol: { kind: 'oauth2', ...oauth2Endpoints('github'), tokenAuth: 'post' },
	extraAuthorizationParams: {},
	scopeParam: 'scope',
	scopeSeparator: ' ',
	responseScopeSeparator: ',',
	alwaysScopes: [],
	defaultScopes: ['read:user'],
	pkce: 'S256',
	identity: {
		source: 'endpoint',
		url: 'https://api.github.com/user',
		idPaths: ['id'],
		labelPath: 'login'
	},
	revocation: {
		kind: 'github_grant',
		urlTemplate: 'https://api.github.com/applications/{client_id}/grant'
	},
	manageAccessUrls: ['https://github.com/settings/applications'],
	requiredValues: [CLIENT_ID, CLIENT_SECRET],
	consoleUrl: 'https://github.com/settings/developers',
	steps: [
		'Register a new OAuth app (or a GitHub App with user authorization).',
		'Set its authorization callback URL to the callback address below.'
	]
};

const SLACK: ConnectedServiceEntry = {
	catalogueId: 'slack',
	displayName: 'Slack',
	protocol: {
		kind: 'oauth2',
		authorizationEndpoint: 'https://slack.com/oauth/v2/authorize',
		tokenEndpoint: 'https://slack.com/api/oauth.v2.access',
		tokenAuth: 'post'
	},
	extraAuthorizationParams: {},
	scopeParam: 'user_scope',
	scopeSeparator: ',',
	responseScopeSeparator: ',',
	alwaysScopes: [],
	defaultScopes: ['users:read'],
	tokenPath: 'authed_user',
	/*
	 * Never: enabling PKCE on a Slack app marks it a public client, one-way, and caps its refresh tokens at 30
	 * days. A confidential vault keeps its app confidential.
	 */
	pkce: 'never',
	identity: {
		source: 'token',
		idPaths: ['team.id|enterprise.id', 'authed_user.id'],
		labelPath: 'team.name|enterprise.name'
	},
	revocation: { kind: 'slack', url: 'https://slack.com/api/auth.revoke' },
	manageAccessUrls: [],
	requiredValues: [CLIENT_ID, CLIENT_SECRET],
	consoleUrl: 'https://api.slack.com/apps',
	steps: [
		'Create a Slack app and add the callback address below as a redirect URL.',
		'List the user token scopes your agents need here; turn on token rotation for refresh tokens.'
	]
};

const MICROSOFT: ConnectedServiceEntry = {
	catalogueId: 'microsoft',
	displayName: 'Microsoft',
	protocol: { kind: 'oidc', knownProviderId: 'microsoft' },
	extraAuthorizationParams: {},
	scopeParam: 'scope',
	scopeSeparator: ' ',
	responseScopeSeparator: ' ',
	/* `offline_access` is what yields a refresh token; `profile` is what puts `oid` in the ID token. */
	alwaysScopes: ['openid', 'profile', 'offline_access'],
	defaultScopes: ['User.Read'],
	pkce: 'S256',
	/* `sub` is pairwise per application; `oid` is the person within a directory, so it is keyed with `tid`. */
	identity: {
		source: 'id_token',
		idPaths: ['tid', 'oid'],
		labelPath: 'preferred_username|name'
	},
	/* No revocation endpoint exists for a single token. */
	revocation: { kind: 'none' },
	manageAccessUrls: [
		'https://myapps.microsoft.com',
		'https://account.live.com/consent/Manage'
	],
	requiredValues: [
		CLIENT_ID,
		CLIENT_SECRET,
		{
			name: 'tenant',
			label: 'Directory',
			secret: false,
			hint: '"common" for work and personal accounts, "organizations", "consumers", or a directory ID.'
		}
	],
	consoleUrl:
		'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade',
	steps: [
		'Register an application with a "Web" redirect URI set to the callback address below.',
		'Create a client secret under "Certificates & secrets".'
	]
};

export const CONNECTED_SERVICE_CATALOGUE: readonly ConnectedServiceEntry[] = [
	GOOGLE,
	GITHUB,
	SLACK,
	MICROSOFT
];

export function connectedServiceEntry(
	catalogueId: string
): ConnectedServiceEntry | undefined {
	return CONNECTED_SERVICE_CATALOGUE.find(
		(entry) => entry.catalogueId === catalogueId
	);
}
