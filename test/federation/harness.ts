import { agent, getHeader } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { getBucketStore, getProjectStore } from 'lib/adapters/index.js';
import { elysia } from 'lib/index.js';
import { TestAdapter } from 'test/models.js';
import type { FederationProvider } from 'lib/federation/types.js';
import type { idpStub } from './idp_stub.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * Shared scaffolding for the federation suites. Extracted when the second spec arrived rather than copied,
 * for the reason the plain page shell was: two copies of "walk the three hops" answer differently after the
 * first edit, and then a refusal test and a success test are no longer testing the same flow.
 */

export const CLIENT = 'fed-app';

/* A provider with every field set to the least surprising value, so a case overrides only what it is about. */
export function provider(
	origin: string,
	overrides: Partial<FederationProvider> = {}
): FederationProvider {
	return {
		id: 'acme-sso',
		displayName: 'Acme SSO',
		enabled: true,
		issuer: origin,
		clientId: 'stub-client',
		clientSecret: 'stub-secret',
		scopes: ['openid', 'email', 'profile'],
		emailTrusted: false,
		provisioning: 'jit',
		allowedEmailDomains: [],
		emailClaim: 'email',
		...overrides
	};
}

/* A bucket plus the project/client wiring that makes an interaction resolve to it. */
export async function seedBucket(
	clientId: string,
	fields: Record<string, unknown>
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `bucket-${clientId}`,
		...fields
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `project-${clientId}`,
		slug: `${clientId}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

export async function startInteraction(clientId = CLIENT) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

/* Non-2xx HTML has no readable body through the Eden client, and most refusals here are exactly that. */
export async function get(path: string, cookie?: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			headers: cookie ? { cookie } : {}
		})
	);
	return {
		status: res.status,
		location: res.headers.get('location') ?? '',
		text: await res.text(),
		contentType: res.headers.get('content-type') ?? '',
		csp: res.headers.get('content-security-policy'),
		setCookie: res.headers.get('set-cookie'),
		// Separated, because `get('set-cookie')` joins several headers into one string and a cookie's
		// attributes cannot be read out of the join.
		setCookies: res.headers.getSetCookie()
	};
}

/*
 * The same, by POST. Carries no cookie either — for the provider that requires this return it is a
 * cross-site form submission, which is exactly why the callback may not depend on one.
 */
export async function post(path: string, form: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: form
		})
	);
	return {
		status: res.status,
		location: res.headers.get('location') ?? '',
		text: await res.text(),
		contentType: res.headers.get('content-type') ?? '',
		csp: res.headers.get('content-security-policy'),
		setCookie: res.headers.get('set-cookie'),
		setCookies: res.headers.getSetCookie()
	};
}

type Stub = Awaited<ReturnType<typeof idpStub>>;

export interface Answer {
	idp: Stub;
	claims: Record<string, unknown>;
	opts?: Parameters<Stub['answerToken']>[2];
}

/*
 * Walk the three hops a browser walks, with the provider answering in between exactly as a real one does: it
 * receives the authorization request, and only then can it mint an assertion echoing that request's nonce.
 *
 * `answer` omitted leaves the token endpoint unstubbed, for a case about the outbound failure itself.
 * `code` omitted defaults to a plausible one; pass `callbackQuery` to drive the callback directly.
 */
export async function walk(
	uid: string,
	cookie: string,
	answer?: Answer,
	options: {
		providerId?: string;
		callbackQuery?: string;
		/*
		 * An upstream that is not `idp_stub.ts` answering. The recognised providers in
		 * ./recognised_stubs.ts have their own shapes — one of them issues no assertion at all — so they
		 * cannot satisfy `Answer`, and every one of them still needs the same two-phase timing: the
		 * authorization request exists before the answer to it does.
		 */
		onAuthorize?: (authorizeUrl: URL) => Promise<void>;
		/*
		 * How the user comes back. One recognised provider requires it posted, and refuses the
		 * authorization request otherwise — so this is that provider's contract, not a variation.
		 */
		returnBy?: 'GET' | 'POST';
	} = {}
) {
	const providerId = options.providerId ?? 'acme-sso';
	const start = await get(`/ui/${uid}/federation/${providerId}/start`, cookie);
	/*
	 * Walking assumes leg one redirected. A case about leg one *failing* calls `get` on the start route
	 * directly, so failing loudly here is better than handing every caller an optional URL to narrow — and
	 * the message names the status rather than leaving a `cannot be parsed as a URL` to decode.
	 */
	if (!start.location) {
		throw new Error(
			`the start route did not redirect (status ${start.status}): ${start.text.slice(0, 200)}`
		);
	}
	const authorizeUrl = new URL(start.location);
	const state = authorizeUrl.searchParams.get('state') ?? '';

	if (answer) {
		await answer.idp.answerToken(authorizeUrl, answer.claims, answer.opts);
	}
	if (options.onAuthorize) {
		await options.onAuthorize(authorizeUrl);
	}

	// The return leg carries no cookie: it is a cross-site top-level navigation from the provider.
	const query =
		options.callbackQuery ??
		`code=upstream-code&state=${encodeURIComponent(state)}`;
	const callback =
		options.returnBy === 'POST'
			? await post('/federation/callback', query)
			: await get(`/federation/callback?${query}`);

	const complete = callback.location.startsWith(
		`/ui/${uid}/federation/complete`
	)
		? await get(callback.location, cookie)
		: undefined;

	return { start, authorizeUrl, state, callback, complete };
}

/*
 * Who got signed in, read from the sessions the flow created.
 *
 * Not from the Interaction's stored `result`: `resume()` acts on that result and clears the interaction, so
 * by the time a test looks it is gone — asserting on it measured nothing and passed only by accident of
 * ordering. The session is the durable record of "this account is signed in", which is the claim being made.
 */
export function signedInAccountIds(): string[] {
	const store = TestAdapter.for('Session').store as Map<string, unknown>;
	const ids: string[] = [];
	for (const [key, value] of store) {
		if (typeof key !== 'string' || !key.startsWith('Session:')) continue;
		const accountId = (value as { accountId?: string } | undefined)?.accountId;
		if (accountId) ids.push(accountId);
	}
	return ids;
}

/*
 * Every refusal in this feature is a rendered page carrying a real status. Asserting the status alone would
 * miss a refusal that answers 200 with an apology, and asserting the body alone would miss one that renders
 * correctly while telling a non-browser client the opposite.
 */
export function expectRefusalPage(
	res: Awaited<ReturnType<typeof get>>,
	status: number
): void {
	expectStatus(res, status);
	if (!res.contentType.includes('text/html')) {
		throw new Error(`expected an HTML refusal, got ${res.contentType}`);
	}
	if (!res.csp) {
		throw new Error('a rendered page must carry a content security policy');
	}
}

function expectStatus(
	res: Awaited<ReturnType<typeof get>>,
	status: number
): void {
	if (res.status !== status) {
		throw new Error(
			`expected status ${status}, got ${res.status}: ${res.text.slice(0, 200)}`
		);
	}
}
