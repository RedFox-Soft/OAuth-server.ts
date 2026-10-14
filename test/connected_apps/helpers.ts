import { expect } from 'bun:test';

import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import {
	adminAuditStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { agent, encodeParams } from '../test_helper.js';
import { shownAccount } from '../consent_form.js';
import { present } from '../shape.ts';

export const PASSWORD = 'correct horse battery staple';
let passwordHash: string | undefined;

/* The bucket the config's clients sign people in to, as a record — the page reads its owner and name. */
export async function defaultBucket(): Promise<UserBucket> {
	const store = getBucketStore();
	return (
		(await store.find(DEFAULT_BUCKET_ID)) ??
		store.create({
			_id: DEFAULT_BUCKET_ID,
			name: 'default',
			ownerGroupId: UNASSIGNED_GROUP_ID
		})
	);
}

export async function addressedBucket(
	id: string,
	address: { slug?: string; host?: string }
): Promise<UserBucket> {
	forgetBucketAddresses();
	return getBucketStore().create({
		_id: id,
		name: `${id} people`,
		ownerGroupId: UNASSIGNED_GROUP_ID,
		...address
	});
}

/* A person who signs in with a password, as anyone would. */
export async function person(
	bucketId = DEFAULT_BUCKET_ID,
	fields: { id?: string; phone?: string } = {}
): Promise<{ email: string; accountId: string }> {
	passwordHash ??= await Bun.password.hash(PASSWORD);
	const email = `person-${Math.random().toString(36).slice(2)}@acme.test`;
	const user = await getUserStore(bucketId).create(
		email,
		passwordHash,
		true,
		fields.id,
		fields.phone ? { profile: { phoneNumbers: [{ value: fields.phone }] } } : {}
	);
	return { email, accountId: user._id };
}

/*
 * A browser: keeps what it is given, sends it all back, forgets what is cleared, and follows redirects the
 * way a browser would — for as long as they stay on this server.
 */
export class Browser {
	#jar = new Map<string, string>();

	constructor(readonly origin: string = ISSUER) {}

	get cookie(): string {
		return [...this.#jar].map(([k, v]) => `${k}=${v}`).join('; ');
	}

	has(name: string): boolean {
		return this.#jar.has(name);
	}

	forget(name: string): void {
		this.#jar.delete(name);
	}

	#absorb(response: Response): Response {
		for (const raw of response.headers.getSetCookie()) {
			const [pair] = raw.split(';');
			const at = pair.indexOf('=');
			const name = pair.slice(0, at);
			const value = pair.slice(at + 1);
			if (!value || /max-age=0/i.test(raw) || raw.includes('1970')) {
				this.#jar.delete(name);
			} else {
				this.#jar.set(name, value);
			}
		}
		return response;
	}

	url(path: string): string {
		return new URL(path, this.origin).toString();
	}

	async request(path: string, init: RequestInit = {}): Promise<Response> {
		const headers = new Headers(init.headers);
		// A case that hands over a jar of its own — one a browser could be made to hold — sends that instead.
		if (this.cookie && !headers.has('cookie'))
			headers.set('cookie', this.cookie);
		return this.#absorb(
			await elysia.handle(
				new Request(this.url(path), { redirect: 'manual', ...init, headers })
			)
		);
	}

	post(
		path: string,
		fields: Record<string, string>,
		headers: Record<string, string> = {}
	): Promise<Response> {
		return this.request(path, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				...headers
			},
			body: new URLSearchParams(fields).toString()
		});
	}

	/*
	 * Follows redirects that stay on a server origin this browser knows, and stops at the first one leaving it
	 * (a client's redirect URI) or at a page.
	 */
	async open(
		path: string,
		init: RequestInit = {}
	): Promise<{ response: Response; url: string }> {
		let url = this.url(path);
		let response = await this.request(url, init);
		for (let hop = 0; hop < 12 && [302, 303].includes(response.status); hop++) {
			const next = new URL(
				present(response.headers.get('location'), 'a location'),
				url
			);
			if (!isServer(next)) return { response, url: next.toString() };
			url = next.toString();
			response = await this.request(url);
		}
		return { response, url };
	}
}

function isServer(url: URL): boolean {
	return (
		url.origin === new URL(ISSUER).origin ||
		url.hostname.endsWith('.example.test')
	);
}

/* The page's address at a bucket: `''` for the root, `/acme` for a path-addressed bucket. */
export function pageOf(prefix = ''): string {
	return `${prefix}/account/apps`;
}

/*
 * Opens the page signed out and signs in through the login form it leads to, as a person would; answers the
 * page they land on.
 */
export async function signInThroughPage(
	browser: Browser,
	email: string,
	prefix = ''
): Promise<Response> {
	const login = await browser.open(pageOf(prefix));
	expect(login.response.status).toBe(200);
	expect(login.url).toMatch(/\/ui\/[^/]+\/login$/);
	const posted = await browser.request(login.url, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			username: email,
			password: PASSWORD
		}).toString()
	});
	const location = present(
		posted.headers.get('location'),
		'a redirect after the login'
	);
	const landed = await browser.open(new URL(location, login.url).toString());
	return landed.response;
}

export interface Access {
	accessToken: string;
	refreshToken?: string;
}

/*
 * Gives a root-bucket application access as a person would: an authorization request from the signed-in
 * browser, the consent page answered "allow" when it appears, and the code redeemed.
 */
export async function giveAccess(
	browser: Browser,
	clientId: string,
	scope = 'openid',
	allow: string[] = []
): Promise<Access> {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope,
		...(scope.includes('offline_access') ? { prompt: 'consent' } : {})
	});
	let step = await browser.open(`/auth?${encodeParams(auth.params)}`);
	if (step.response.status === 200 && /\/consent$/.test(step.url)) {
		const uid = step.url.split('/').at(-2) ?? '';
		const fields = new URLSearchParams({
			action: 'allow',
			accountId: await shownAccount(uid)
		});
		for (const key of allow) fields.append('allow', key);
		const decided = await browser.request(step.url, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: fields.toString()
		});
		step = await browser.open(
			new URL(
				present(decided.headers.get('location'), 'a resume'),
				step.url
			).toString()
		);
	}
	const code = present(
		new URL(step.url).searchParams.get('code'),
		`a code for ${clientId} (ended at ${step.url})`
	);
	const { data } = await auth.getToken(code);
	const tokens = data as {
		access_token?: string;
		refresh_token?: string;
	} | null;
	return {
		accessToken: present(tokens?.access_token, 'an access token'),
		...(tokens?.refresh_token ? { refreshToken: tokens.refresh_token } : {})
	};
}

/* The anti-forgery value the confirmation form carries. */
export function xsrfFrom(html: string): string {
	return present(
		/name="xsrf" value="([^"]+)"/.exec(html)?.[1],
		'the form’s xsrf value'
	);
}

export async function openConfirmation(
	browser: Browser,
	clientId: string,
	prefix = ''
): Promise<{ response: Response; html: string }> {
	const response = await browser.request(
		`${pageOf(prefix)}?revoke=${encodeURIComponent(clientId)}`
	);
	return { response, html: await response.text() };
}

export function refresh(clientId: string, refreshToken: string) {
	return agent.token.post(
		{ grant_type: 'refresh_token', refresh_token: refreshToken },
		{ headers: AuthorizationRequest.basicAuthHeader(clientId, 'secret') }
	);
}

export async function introspect(token: string): Promise<unknown> {
	const { data } = await agent.token.introspect.post(
		{ token },
		{ headers: AuthorizationRequest.basicAuthHeader('own-app', 'secret') }
	);
	return data;
}

export async function auditOf(accountId: string) {
	return (await adminAuditStore.list({ targetId: accountId })).entries;
}

/* What a reader sees, tags removed and whitespace folded. The isolation around a name sits inside a sentence. */
export function textOf(html: string): string {
	return html
		.replace(/<\/?bdi>/g, '')
		.replace(/<[^>]+>/g, ' ')
		.replace(/&amp;/g, '&')
		.replace(/&#39;|&#x27;/g, "'")
		.replace(/&quot;/g, '"')
		.replace(/\s+/g, ' ')
		.trim();
}
