import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ttl } from 'lib/configs/liveTime.ts';

const CLIENT_ID = 'ui-open-app';
const PASSWORD = 'correct horse battery';

/*
 * Read off the response header, never off a cookie string threaded through by hand. A hand-built
 * cookie string carries `name=value` and no attributes at all, so it cannot observe the one attribute
 * this whole file is about — the same blindness wiki/concepts/cookie-path-scoping.md names as the
 * reason every existing suite passed while the browser kept the wrong cookie.
 */
function setCookieFor(response: Response, name: string): string {
	const all = response.headers.getSetCookie();
	const found = all.find((c) => c.startsWith(`${name}=`));
	if (!found) {
		throw new Error(
			`expected a ${name} Set-Cookie, got ${JSON.stringify(all)}`
		);
	}
	return found;
}

// The `name=value` pair only, for re-sending as a request cookie.
function pairOf(header: string): string {
	return header.split(';')[0];
}

/*
 * Both attributes, not just the one being set. RFC 6265 makes a cookie non-persistent only when it
 * carries neither, so asserting on `Expires` alone would be satisfied by a future change that reached
 * for `Max-Age` instead.
 */
function expectNotRetained(header: string) {
	expect(header).not.toMatch(/;\s*Expires=/i);
	expect(header).not.toMatch(/;\s*Max-Age=/i);
}

function expectRetained(header: string) {
	expect(header).toMatch(/;\s*Expires=/i);
}

// Carried on every write of the session cookie, and would regress together with the lifetime.
function expectHardened(header: string) {
	expect(header).toContain('HttpOnly');
	expect(header).toContain('Secure');
	expect(header).toContain('SameSite=Strict');
	expect(header).toContain('Path=/');
}

async function startInteraction(sessionCookie?: string) {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid',
		// Without it an established session skips the sign-in screen, and a second answer can never be given.
		...(sessionCookie ? { prompt: 'login' } : {})
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		...(sessionCookie ? { headers: { cookie: sessionCookie } } : {})
	});
	const location = getHeader(response, 'location');
	return {
		uid: location.split('/')[2],
		interactionCookie: pairOf(setCookieFor(response, '_interaction'))
	};
}

async function register(email: string) {
	const { uid, interactionCookie } = await startInteraction();
	const { response } = await agent
		.ui({ uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie: interactionCookie } }
		);
	expect(response.status).toBe(303);
}

/*
 * `remember` is omitted entirely when declining rather than sent as `off`: an unchecked HTML checkbox
 * submits nothing at all, so `off` would exercise a request no browser produces — and would pass for
 * the wrong reason.
 */
async function signIn(
	email: string,
	{ remember, sessionCookie }: { remember: boolean; sessionCookie?: string }
) {
	const { uid, interactionCookie } = await startInteraction(sessionCookie);
	const cookie = sessionCookie
		? [sessionCookie, interactionCookie].join('; ')
		: interactionCookie;

	const { response } = await agent.ui({ uid }).login.post(
		{
			username: email,
			password: PASSWORD,
			...(remember ? { remember: 'on' } : {})
		},
		{ headers: { cookie } }
	);
	expect(response.status).toBe(303);
	return setCookieFor(response, '_session');
}

/**
 * @proves The end user's answer to "Remember me" decides whether their browser keeps the sign-in
 * after the browser closes, on every path that offers the choice; a path that offers none keeps it.
 */
describe('the "Remember me" choice at sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'pages' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Remember Me Bucket',
			emailVerificationRequired: false
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Remember Me',
			slug: `remember-me-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId: bucket._id,
			clientIds: [CLIENT_ID]
		});
	});

	it('is not retained past the browsing session when the end user declines to be remembered', async () => {
		const email = 'remember-decline@x.io';
		await register(email);
		const header = await signIn(email, { remember: false });

		expectNotRetained(header);
		// A sign-in on a shared machine is the one most in need of the rest of the attributes, not least.
		expectHardened(header);
	});

	it('is not retained when the end user signs in again declining, having been remembered before', async () => {
		const email = 'remember-downgrade@x.io';
		await register(email);
		const first = await signIn(email, { remember: true });

		const header = await signIn(email, {
			remember: false,
			sessionCookie: pairOf(first)
		});

		expectNotRetained(header);
	});

	it('is retained to the sign-in lifetime when the end user asks to be remembered', async () => {
		const email = 'remember-accept@x.io';
		await register(email);
		const header = await signIn(email, { remember: true });

		expectRetained(header);
		expectHardened(header);

		// Remembering does not mean forever: the server's own ceiling on a sign-in is still the ceiling.
		const expires = new Date(
			/;\s*Expires=([^;]+)/i.exec(header)?.[1] as string
		);
		const expected = Date.now() + ttl.Session * 1000;
		expect(Math.abs(expires.getTime() - expected)).toBeLessThan(5 * 60 * 1000);
	});

	it('is retained when the end user signs in again asking to be remembered, having declined before', async () => {
		const email = 'remember-upgrade@x.io';
		await register(email);
		const first = await signIn(email, { remember: false });

		const header = await signIn(email, {
			remember: true,
			sessionCookie: pairOf(first)
		});

		expectRetained(header);
	});
});
