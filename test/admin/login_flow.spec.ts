import {
	describe,
	it,
	expect,
	beforeAll,
	afterEach,
	spyOn,
	type Mock
} from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { routeNames } from 'lib/consts/param_list.ts';
import { Session } from 'lib/models/session.ts';
import { mintAdminIdToken } from './id_token_fixture.ts';

// Pull one `name=value` pair out of a Set-Cookie response header array.
function cookiePair(setCookies: string[], name: string): string {
	const raw = setCookies.find((c) => c.startsWith(`${name}=`));
	if (!raw) throw new Error(`expected Set-Cookie "${name}"`);
	return raw.split(';')[0];
}

let superAdminId: string;
let fetchSpy: Mock<typeof fetch> | undefined;

// Run the console's OIDC sign-in end to end and hand back its `_admin_session` cookie pair.
// The token exchange is stubbed (ISSUER points at a fake host under test) but the identity
// token is genuinely signed by the live keystore and carries this attempt's nonce.
async function signIn(): Promise<string> {
	const login = await agent.admin.login.get();
	const oauthCookie = cookiePair(
		login.response.headers.getSetCookie(),
		'admin_oauth'
	);
	const params = new URL(getHeader(login.response, 'location')).searchParams;
	const state = params.get('state') as string;

	const idToken = await mintAdminIdToken({
		sub: superAdminId,
		nonce: params.get('nonce') ?? undefined
	});
	fetchSpy = spyOn(globalThis, 'fetch').mockImplementation((async () => ({
		ok: true,
		json: async () => ({ access_token: 'x', id_token: idToken })
	})) as unknown as typeof fetch);

	const cb = await agent.admin.callback.get({
		query: { code: 'valid-code', state },
		headers: { cookie: oauthCookie }
	});
	return cookiePair(cb.response.headers.getSetCookie(), '_admin_session');
}

describe('admin OIDC login (BFF)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		// Cross-suite isolation: drop cached admin store singletons other specs
		// seeded, re-seed the admin bucket/project/client, then plant our own
		// super_admin whose _id will be the id_token `sub` in the stubbed exchange.
		resetAdminMemoryStores();
		await ensureAdminSeed();
		const superAdmin = await getUserStore(ADMIN_BUCKET_ID).create(
			'root@x.io',
			await Bun.password.hash('correct horse battery'),
			['super_admin']
		);
		superAdminId = superAdmin._id;
	});

	afterEach(() => {
		// bun's mock.restore() would wipe beforeAll spies; restore the per-test
		// fetch spy explicitly instead.
		if (fetchSpy) {
			fetchSpy.mockRestore();
			fetchSpy = undefined;
		}
	});

	it('me is 401 without a session', async () => {
		const res = await agent.admin.api.me.get();
		expect(res.status).toBe(401);
	});

	it('login redirects to the OIDC authorization endpoint with PKCE + state and sets admin_oauth', async () => {
		const res = await agent.admin.login.get();
		expect(res.status).toBe(302);

		const location = getHeader(res.response, 'location');
		// Must target the provider's real authorization route (routeNames.authorization,
		// '/auth') — not a made-up '/authorize' path, which 404s and breaks login.
		expect(new URL(location).pathname).toBe(routeNames.authorization);
		const params = new URL(location).searchParams;
		expect(params.get('client_id')).toBe('admin-panel');
		expect(params.get('response_type')).toBe('code');
		expect(params.get('code_challenge_method')).toBe('S256');
		expect(params.get('code_challenge')).toBeTruthy();
		expect(params.get('state')).toBeTruthy();

		const setCookies = res.response.headers.getSetCookie();
		expect(setCookies.some((c) => c.startsWith('admin_oauth='))).toBe(true);
	});

	it('callback with a mismatched state is 400', async () => {
		const login = await agent.admin.login.get();
		const oauthCookie = cookiePair(
			login.response.headers.getSetCookie(),
			'admin_oauth'
		);
		const res = await agent.admin.callback.get({
			query: { code: 'anything', state: 'wrong-state' },
			headers: { cookie: oauthCookie }
		});
		expect(res.status).toBe(400);
	});

	it('callback exchanges the code, sets a session, and /me returns roles', async () => {
		// Drive the real /admin/login to obtain the signed admin_oauth cookie and
		// the matching state, so the callback's CSRF check passes.
		const login = await agent.admin.login.get();
		const oauthCookie = cookiePair(
			login.response.headers.getSetCookie(),
			'admin_oauth'
		);
		const params = new URL(getHeader(login.response, 'location')).searchParams;
		const state = params.get('state') as string;

		// Stub the internal token exchange: ISSUER points at a fake host in tests,
		// so the callback's fetch(`${ISSUER}/token`) can never reach a real server.
		// The token itself is genuinely signed by the live keystore and carries this
		// attempt's nonce — the callback verifies both.
		const idToken = await mintAdminIdToken({
			sub: superAdminId,
			nonce: params.get('nonce') ?? undefined
		});
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation((async () => ({
			ok: true,
			json: async () => ({ access_token: 'x', id_token: idToken })
		})) as unknown as typeof fetch);

		// Include `iss` — the provider appends the RFC 9207 issuer identifier to the
		// authorization response redirect, and the callback query schema must accept
		// it (a strict { code, state } schema 422s under `normalize: false`).
		const cb = await agent.admin.callback.get({
			query: { code: 'valid-code', state, iss: 'http://e.ly' },
			headers: { cookie: oauthCookie }
		});
		expect(cb.status).toBe(302);
		expect(getHeader(cb.response, 'location')).toBe('/admin');

		const sessionCookie = cookiePair(
			cb.response.headers.getSetCookie(),
			'_admin_session'
		);

		const me = await agent.admin.api.me.get({
			headers: { cookie: sessionCookie }
		});
		expect(me.status).toBe(200);
		const meData = me.data as {
			roles: string[];
			bucketId: string;
			email: string;
		} | null;
		expect(meData?.roles).toContain('super_admin');
		expect(meData?.bucketId).toBe(ADMIN_BUCKET_ID);
		// The admin shell header renders the email (not the raw user id).
		expect(meData?.email).toBe('root@x.io');
	});

	it('logout destroys the session', async () => {
		const login = await agent.admin.login.get();
		const oauthCookie = cookiePair(
			login.response.headers.getSetCookie(),
			'admin_oauth'
		);
		const params = new URL(getHeader(login.response, 'location')).searchParams;
		const state = params.get('state') as string;

		const idToken = await mintAdminIdToken({
			sub: superAdminId,
			nonce: params.get('nonce') ?? undefined
		});
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation((async () => ({
			ok: true,
			json: async () => ({ access_token: 'x', id_token: idToken })
		})) as unknown as typeof fetch);

		const cb = await agent.admin.callback.get({
			query: { code: 'valid-code', state },
			headers: { cookie: oauthCookie }
		});
		const sessionCookie = cookiePair(
			cb.response.headers.getSetCookie(),
			'_admin_session'
		);

		const before = await agent.admin.api.me.get({
			headers: { cookie: sessionCookie }
		});
		expect(before.status).toBe(200);

		const out = await agent.admin.api.logout.post(undefined, {
			headers: { cookie: sessionCookie }
		});
		expect(out.status).toBe(200);

		const after = await agent.admin.api.me.get({
			headers: { cookie: sessionCookie }
		});
		expect(after.status).toBe(401);
	});

	/*
	 * The test above re-sends the same cookie string by hand, so it can only observe the store
	 * being emptied — it is blind to whether the browser was ever told to drop the cookie, and to
	 * the provider session that actually decides whether the next visit re-authenticates. Both of
	 * those were broken. These cover them.
	 */
	it('logout clears both cookies with the attributes they were set with', async () => {
		const sessionCookie = await signIn();

		const out = await agent.admin.api.logout.post(undefined, {
			headers: { cookie: sessionCookie }
		});
		expect(out.status).toBe(200);

		const cleared = out.response.headers.getSetCookie();

		// `Path` must match the cookie that is live in the browser. Omit it and the browser
		// applies the default-path of the request URI — `/admin/api` — which names a different
		// cookie, so the real `_admin_session` (`Path=/admin`) survives the sign-out untouched.
		const adminCleared = cleared.find((c) => c.startsWith('_admin_session='));
		expect(adminCleared).toBeDefined();
		expect(adminCleared).toContain('Path=/admin');
		expect(adminCleared).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);

		const providerCleared = cleared.find((c) => c.startsWith('_session='));
		expect(providerCleared).toBeDefined();
		expect(providerCleared).toMatch(/Path=\/(;|$)/);
		expect(providerCleared).toMatch(/Max-Age=0|Expires=Thu, 01 Jan 1970/i);
	});

	it('logout destroys the provider session, not just the console session', async () => {
		const sessionCookie = await signIn();

		// A live provider session for the same operator — the thing that, left alone, let
		// `/admin/login` walk straight back through `/auth` and mint a new console session.
		const providerSession = new Session({ uid: 'logout-spec' });
		providerSession.loginAccount({ accountId: superAdminId });
		await providerSession.save();
		const providerSessionId = providerSession.id as string;
		expect(await Session.tryFind(providerSessionId)).toBeDefined();

		const out = await agent.admin.api.logout.post(undefined, {
			headers: { cookie: `${sessionCookie}; _session=${providerSessionId}` }
		});
		expect(out.status).toBe(200);

		expect(await Session.tryFind(providerSessionId)).toBeUndefined();
	});

	it('logout is idempotent when nothing is signed in', async () => {
		const out = await agent.admin.api.logout.post(undefined, {});
		expect(out.status).toBe(200);
		expect(out.data).toEqual({ ok: true });
	});
});
