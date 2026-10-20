/*
 * The situations a new application is created from (spec 107, research R1). A situation only fills in the fields an
 * administrator could set by hand and sends them to the ordinary create route: the server never learns which one was
 * chosen, and nothing stores it. That is why changing a situation's defaults can never change what a script or an
 * agent creating a client gets.
 */

export type SituationId =
	'server' | 'spa' | 'native' | 'device' | 'service' | 'resource' | 'custom';

export type SituationGroup = 'people' | 'machine' | 'resource';

export type GrantType =
	| 'authorization_code'
	| 'refresh_token'
	| 'client_credentials'
	| 'urn:ietf:params:oauth:grant-type:device_code'
	| 'urn:openid:params:grant-type:ciba';

export type AuthMethod =
	| 'none'
	| 'client_secret_basic'
	| 'client_secret_post'
	| 'client_secret_jwt'
	| 'private_key_jwt';

/* The create-route fields a situation sets. Everything else keeps the route's defaults. */
export interface Expansion {
	applicationType: 'web' | 'native';
	grantTypes: GrantType[];
	tokenEndpointAuthMethod: AuthMethod;
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	corsOrigins: string[];
}

export interface Situation {
	id: SituationId;
	group: SituationGroup;
	title: string;
	description: string;
	/* The protocol it implies, small and grey: it teaches the vocabulary without asking for it. */
	footnote: string;
	/* Present for the situations whose callback follows from where the app runs during development. */
	devAddress?: string;
	/* Absent for the two that create no application from a template: an API is declared, "custom" is the form. */
	expand?: (devAddress: string) => Expansion;
}

const DEVICE_CODE: GrantType = 'urn:ietf:params:oauth:grant-type:device_code';

/* The address without a trailing slash, so `<dev>/callback` never doubles it. */
export function originOf(devAddress: string): string {
	return devAddress.trim().replace(/\/+$/, '');
}

export const SITUATIONS: readonly Situation[] = [
	{
		id: 'server',
		group: 'people',
		title: 'Web app with a server',
		description:
			'Next.js, Nuxt, SvelteKit, Express, Django, Rails, Laravel — your server can keep a secret.',
		footnote: 'Confidential · code + PKCE · refresh tokens',
		devAddress: 'http://localhost:3000',
		expand: (dev) => ({
			applicationType: 'web',
			grantTypes: ['authorization_code', 'refresh_token'],
			tokenEndpointAuthMethod: 'client_secret_basic',
			redirectUris: [`${originOf(dev)}/callback`],
			postLogoutRedirectUris: [originOf(dev)],
			corsOrigins: []
		})
	},
	{
		id: 'spa',
		group: 'people',
		title: 'Single-page app',
		description:
			'React, Vue, Angular or Svelte built with Vite, with no server of yours in the sign-in path.',
		footnote: 'Public · code + PKCE · refresh tokens · browser origin',
		devAddress: 'http://localhost:5173',
		/*
		 * A web application, not a native one, although it has no secret: the lifetime cap on a public client's
		 * refresh tokens reads the application type, and a browser is what that cap exists for.
		 */
		expand: (dev) => ({
			applicationType: 'web',
			grantTypes: ['authorization_code', 'refresh_token'],
			tokenEndpointAuthMethod: 'none',
			redirectUris: [`${originOf(dev)}/callback`],
			postLogoutRedirectUris: [originOf(dev)],
			corsOrigins: [originOf(dev)]
		})
	},
	{
		id: 'native',
		group: 'people',
		title: 'Mobile, desktop or command-line app',
		description:
			"iOS, Android, Electron, a CLI — or an AI agent that runs on the user's machine.",
		footnote: 'Public · code + PKCE · any loopback port',
		// RFC 8252 §7.3: a loopback redirect is matched on any port, so one registration serves every run.
		expand: () => ({
			applicationType: 'native',
			grantTypes: ['authorization_code', 'refresh_token'],
			tokenEndpointAuthMethod: 'none',
			redirectUris: ['http://127.0.0.1/callback'],
			postLogoutRedirectUris: [],
			corsOrigins: []
		})
	},
	{
		id: 'device',
		group: 'people',
		title: 'TV or device without a keyboard',
		description: 'The person signs in on their phone with a short code.',
		footnote: 'Public · device code',
		expand: () => ({
			applicationType: 'native',
			grantTypes: [DEVICE_CODE],
			tokenEndpointAuthMethod: 'none',
			redirectUris: [],
			postLogoutRedirectUris: [],
			corsOrigins: []
		})
	},
	{
		id: 'service',
		group: 'machine',
		title: 'Service calling your API',
		description:
			'A backend job, cron task or agent with its own credentials, with no user involved.',
		footnote: 'Confidential · client credentials',
		expand: () => ({
			applicationType: 'web',
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'client_secret_basic',
			redirectUris: [],
			postLogoutRedirectUris: [],
			corsOrigins: []
		})
	},
	{
		id: 'resource',
		group: 'resource',
		title: 'My MCP server or API',
		description:
			'Not an application: you declare it so this project issues tokens for it, and Claude, Cursor or your own apps connect to it.',
		footnote: 'Declared on the APIs tab'
	},
	{
		id: 'custom',
		group: 'people',
		title: 'Configure everything yourself',
		description: 'Every setting, as the protocol names it.',
		footnote: 'Full form'
	}
];

export function situation(id: SituationId): Situation {
	const found = SITUATIONS.find((s) => s.id === id);
	if (!found) throw new Error(`unknown situation ${id}`);
	return found;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/*
 * Why a development address cannot be used, or null. The server makes the final decision on every redirect it is
 * given; this only says sooner, in words, the two mistakes a person makes here.
 */
export function devAddressProblem(text: string): string | null {
	let url: URL;
	try {
		url = new URL(text.trim());
	} catch {
		return 'Enter an address such as http://localhost:3000.';
	}
	if (url.protocol !== 'http:' && url.protocol !== 'https:') {
		return 'The address starts with http:// or https://.';
	}
	if (url.protocol === 'http:' && !LOOPBACK.has(url.hostname)) {
		return 'Plain http is accepted only for localhost; use https for any other host.';
	}
	if (url.search || url.hash) {
		return 'Leave out the query and fragment: only the origin and path are used.';
	}
	return null;
}
