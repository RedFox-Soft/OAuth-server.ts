import { expect } from 'bun:test';

import { agent } from '../test_helper.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { present } from '../shape.ts';
import {
	Browser,
	codeFor,
	openApp,
	typePassword,
	type Reached
} from '../require_code/helpers.ts';

export {
	Browser,
	codeFor,
	mailOn,
	person,
	project,
	setUpAndContinue,
	textOf,
	uidIn
} from '../require_code/helpers.ts';

export const AGENT = 'agent';
export const FILES = 'https://files.acme.test/mcp';
export const NOTES = 'https://notes.acme.test/mcp';
export const SECRET = 'JBSWY3DPEHPK3PXP';

/* Files with the requirement a case asks for, Notes with none; both declared afresh for every case. */
export async function apis(
	requirement: { requireCode?: boolean; signInEveryMinutes?: number } = {},
	tokenFormat: 'jwt' | 'opaque' = 'jwt',
	bucketId: string = DEFAULT_BUCKET_ID
): Promise<void> {
	const store = getProtectedResourceStore();
	for (const [identifier, name, scope] of [
		[FILES, 'Files', 'files:read'],
		[NOTES, 'Notes', 'notes:read']
	] as const) {
		await store.destroy(ROOT_NAMESPACE, identifier);
		await store.create({
			namespace: ROOT_NAMESPACE,
			identifier,
			bucketId,
			name,
			scopes: [scope],
			tokenFormat,
			...(identifier === FILES ? requirement : {})
		});
	}
}

export async function requireOnFiles(requirement: {
	requireCode?: boolean;
	signInEveryMinutes?: number | null;
}): Promise<void> {
	await getProtectedResourceStore().update(ROOT_NAMESPACE, FILES, requirement);
}

/* The agent's sign-in for both APIs, as an MCP client starts it. */
export function connect(browser: Browser, extra: Record<string, string> = {}) {
	return openApp(browser, AGENT, {
		scope: 'openid offline_access files:read notes:read',
		resource: FILES,
		prompt: 'consent',
		...extra
	});
}

/* Answers the code step a password sign-in landed on, and follows where it leads. */
export async function typeCode(
	browser: Browser,
	landedUrl: string,
	secret = SECRET
): Promise<{ response: Response; url: string }> {
	const uid = present(
		/\/ui\/([^/]+)\/totp$/.exec(landedUrl)?.[1],
		`the code step (ended at ${landedUrl})`
	);
	const answered = await browser.post(`/ui/${uid}/totp`, {
		code: codeFor(secret)
	});
	return browser.open(
		new URL(
			present(answered.headers.get('location'), 'a resume'),
			browser.url(`/ui/${uid}/`)
		).toString()
	);
}

/* A full sign-in: password, then the code when the person holds one. */
export async function signIn(
	browser: Browser,
	email: string,
	withCode: boolean,
	extra: Record<string, string> = {}
): Promise<Reached> {
	const opened = await connect(browser, extra);
	let landed = await typePassword(browser, opened.url, email);
	if (withCode) landed = await typeCode(browser, landed.url);
	return { auth: opened.auth, ...landed };
}

export interface Tokens {
	access_token: string;
	refresh_token?: string;
}

export async function tokensFrom(
	auth: AuthorizationRequest,
	url: string
): Promise<Tokens> {
	const code = present(
		new URL(url).searchParams.get('code'),
		`a code (ended at ${url})`
	);
	const { data, error } = await redeem(auth, code, FILES);
	expect(error).toBeNull();
	return data as Tokens;
}

/* The code redeemed for a token for one API, as an MCP client asks for it. */
export function redeem(
	auth: AuthorizationRequest,
	code: string,
	resource: string
) {
	return agent.token.post(
		{
			code,
			grant_type: 'authorization_code',
			code_verifier: auth.code_verifier,
			redirect_uri: auth.params.redirect_uri,
			resource
		},
		{ headers: AuthorizationRequest.basicAuthHeader(AGENT, 'secret') }
	);
}

export function renew(refreshToken: string, resource?: string) {
	return agent.token.post(
		{
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			...(resource === undefined ? {} : { resource })
		},
		{ headers: AuthorizationRequest.basicAuthHeader(AGENT, 'secret') }
	);
}

export function payloadOf(jwt: string): Record<string, unknown> {
	const part = present(jwt.split('.')[1], 'a JWT payload');
	return JSON.parse(Buffer.from(part, 'base64url').toString()) as Record<
		string,
		unknown
	>;
}
