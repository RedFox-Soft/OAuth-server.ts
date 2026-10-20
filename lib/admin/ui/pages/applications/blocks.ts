import type { ClientView, Connection } from './clientForm.js';

/*
 * The text the Connect tab hands a developer (spec 107, research R6): values, never library code, which belongs in the
 * documentation where it can be kept current in three languages. Pure, so what may and may not appear in it is proved
 * without a browser.
 */

/*
 * Neutral, namespaced names. A front-end build tool copies variables with certain prefixes into the bundle it ships to
 * every visitor, so none of these may carry one; the agent block tells the agent to map them to its library's names.
 */
export const ENV_NAMES = {
	issuer: 'FOXAUTH_ISSUER',
	clientId: 'FOXAUTH_CLIENT_ID',
	secret: 'FOXAUTH_CLIENT_SECRET',
	redirectUri: 'FOXAUTH_REDIRECT_URI'
} as const;

/*
 * The configuration block. The secret line is present only when a secret is given — on the visit that minted it —
 * and otherwise a comment says where the secret is kept, so the block never suggests the console still has it.
 */
export function envBlock(
	connection: Pick<Connection, 'issuer' | 'clientId' | 'redirectUris'>,
	secret?: string,
	hasSecret = secret !== undefined
): string {
	const lines = [
		`${ENV_NAMES.issuer}=${connection.issuer ?? ''}`,
		`${ENV_NAMES.clientId}=${connection.clientId}`
	];
	if (secret !== undefined) {
		lines.push(`${ENV_NAMES.secret}=${secret}`);
	} else if (hasSecret) {
		lines.push(
			`# ${ENV_NAMES.secret}: the secret shown once when it was created; rotate it if it is lost`
		);
	}
	const redirect = connection.redirectUris.at(0);
	if (redirect) lines.push(`${ENV_NAMES.redirectUri}=${redirect}`);
	return lines.join('\n');
}

function only(view: Pick<ClientView, 'grantTypes'>, grant: string): boolean {
	return (
		view.grantTypes.length > 0 && view.grantTypes.every((g) => g === grant)
	);
}

/* Whether the application signs nobody in: its only grant is client credentials. */
export function isService(view: Pick<ClientView, 'grantTypes'>): boolean {
	return only(view, 'client_credentials');
}

/* An application in words, read off what it stores (no situation is stored): how it authenticates and what it does. */
export function describe(view: ClientView): string {
	const confidential =
		view.hasSecret === true || view.tokenEndpointAuthMethod !== 'none';
	const who = confidential ? 'Confidential' : 'Public';
	if (isService(view)) return `${who} service · client credentials`;
	const kind =
		view.applicationType === 'native'
			? 'native application'
			: 'web application';
	const flows: string[] = [];
	if (view.grantTypes.includes('authorization_code')) {
		flows.push('sign-in with PKCE');
	}
	if (
		view.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')
	) {
		flows.push('device sign-in');
	}
	if (view.grantTypes.includes('urn:openid:params:grant-type:ciba')) {
		flows.push('back-channel sign-in');
	}
	if (view.grantTypes.includes('client_credentials')) {
		flows.push('client credentials');
	}
	return flows.length
		? `${who} ${kind} · ${flows.join(' · ')}`
		: `${who} ${kind}`;
}

/* The scopes a sign-in asks for; `offline_access` only where a refresh token is wanted and the client may hold one. */
export function scopesToRequest(view: Pick<ClientView, 'grantTypes'>): {
	base: string;
	withRefresh: string | null;
} {
	const base = 'openid email profile';
	return {
		base,
		withRefresh: view.grantTypes.includes('refresh_token')
			? `${base} offline_access`
			: null
	};
}

/*
 * What a developer pastes into their coding agent. Every value the agent needs, and the steps, in plain text; the
 * secret never — the developer puts it into the environment themselves, so it does not pass through a chat log.
 */
export function agentBlock(
	view: ClientView,
	connection: Connection,
	api?: string
): string {
	const lines: string[] = [
		'Connect this app to FoxAuth (OpenID Connect).',
		'',
		`Issuer: ${connection.issuer ?? '(the project has no address yet)'}`,
		`Discovery: ${connection.discoveryUrl ?? '(none yet)'}`,
		`Client ID: ${connection.clientId}`
	];
	if (connection.redirectUris.length) {
		lines.push(`Redirect URIs: ${connection.redirectUris.join(', ')}`);
	}
	if (connection.postLogoutRedirectUris.length) {
		lines.push(
			`Sign-out return URIs: ${connection.postLogoutRedirectUris.join(', ')}`
		);
	}
	const confidential = view.hasSecret === true;
	if (isService(view)) {
		lines.push(
			'',
			'Steps:',
			'1. Read the endpoints from the discovery document.',
			`2. POST to the token endpoint with grant_type=client_credentials${api ? ` and resource=${api}` : ' and resource=<the API identifier>'}, authenticating with the client ID and secret (HTTP Basic).`,
			'3. Send the access token to the API as "Authorization: Bearer <token>".'
		);
	} else {
		const scopes = scopesToRequest(view);
		lines.push(
			`Scopes: ${scopes.base}${scopes.withRefresh ? ` (add offline_access for a refresh token: ${scopes.withRefresh})` : ''}`,
			'',
			'Steps:',
			"1. Use the project's OpenID Connect library for this stack; configure it from the discovery document.",
			'2. Use the authorization code flow with PKCE (S256) and the redirect URI above, exactly as registered.',
			confidential
				? '3. This is a confidential client: authenticate to the token endpoint with the client ID and secret.'
				: '3. This is a public client: no secret; PKCE is what protects the code.',
			'4. Validate the ID token issuer against the issuer above.'
		);
	}
	lines.push(
		'',
		`Environment variables (map them to the library's own names): ${ENV_NAMES.issuer}, ${ENV_NAMES.clientId}${confidential ? `, ${ENV_NAMES.secret}` : ''}${connection.redirectUris.length ? `, ${ENV_NAMES.redirectUri}` : ''}.`
	);
	if (confidential) {
		lines.push(
			`The client secret is not included here: I will put it in ${ENV_NAMES.secret} myself.`
		);
	}
	return lines.join('\n');
}

/*
 * When an application was last used, in words a person reads at a glance. The record is written at most once a minute
 * per server, so anything under two minutes is "just now" rather than a precision it does not have.
 */
export function lastUsedText(
	lastUsed: { lastUsedAt: number } | null,
	now: number = Date.now() / 1000
): string {
	if (!lastUsed) return 'Not used yet';
	const seconds = Math.max(0, now - lastUsed.lastUsedAt);
	if (seconds < 120) return 'just now';
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${String(minutes)} minutes ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 48) return `${String(hours)} hours ago`;
	return new Date(lastUsed.lastUsedAt * 1000).toISOString().slice(0, 10);
}

/*
 * The guide for an application's kind on the public documentation. The console states values; how a library is wired
 * to them lives there, where it is kept current in three languages.
 */
const GUIDES = 'https://foxauth.dev/docs/get-started';

export function guideFor(view: Pick<ClientView, 'grantTypes'>): {
	href: string;
	label: string;
} {
	return isService(view)
		? { href: `${GUIDES}/first-token/`, label: 'Guide: your first token' }
		: {
				href: `${GUIDES}/first-client/`,
				label: 'Guide: connect your first application'
			};
}
