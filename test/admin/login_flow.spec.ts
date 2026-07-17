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

// Pull one `name=value` pair out of a Set-Cookie response header array.
function cookiePair(setCookies: string[], name: string): string {
	const raw = setCookies.find((c) => c.startsWith(`${name}=`));
	if (!raw) throw new Error(`expected Set-Cookie "${name}"`);
	return raw.split(';')[0];
}

let superAdminId: string;
let fetchSpy: Mock<typeof fetch> | undefined;

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

	it('login redirects to /authorize with PKCE + state and sets admin_oauth', async () => {
		const res = await agent.admin.login.get();
		expect(res.status).toBe(302);

		const location = getHeader(res.response, 'location');
		expect(location.startsWith('http://e.ly/authorize')).toBe(true);
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
		const state = new URL(
			getHeader(login.response, 'location')
		).searchParams.get('state') as string;

		// Stub the internal token exchange: ISSUER points at a fake host in tests,
		// so the callback's fetch(`${ISSUER}/token`) can never reach a real server.
		// The callback only base64url-decodes the id_token payload for `sub`.
		const payload = Buffer.from(JSON.stringify({ sub: superAdminId })).toString(
			'base64url'
		);
		const idToken = `header.${payload}.sig`;
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation((async () => ({
			ok: true,
			json: async () => ({ access_token: 'x', id_token: idToken })
		})) as unknown as typeof fetch);

		const cb = await agent.admin.callback.get({
			query: { code: 'valid-code', state },
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
		const meData = me.data as { roles: string[]; bucketId: string } | null;
		expect(meData?.roles).toContain('super_admin');
		expect(meData?.bucketId).toBe(ADMIN_BUCKET_ID);
	});

	it('logout destroys the session', async () => {
		const login = await agent.admin.login.get();
		const oauthCookie = cookiePair(
			login.response.headers.getSetCookie(),
			'admin_oauth'
		);
		const state = new URL(
			getHeader(login.response, 'location')
		).searchParams.get('state') as string;

		const payload = Buffer.from(JSON.stringify({ sub: superAdminId })).toString(
			'base64url'
		);
		const idToken = `header.${payload}.sig`;
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
});
