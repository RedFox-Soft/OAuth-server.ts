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
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { grantSuperAdmin } from 'lib/admin/super_admins.ts';
import { rootKeys } from 'lib/keys/issuer_keys.ts';
import { fetchAnswering } from 'test/fetch_mock.ts';
import { present } from 'test/shape.ts';
import { mintAdminIdToken } from '../admin/id_token_fixture.ts';

function cookiePair(setCookies: string[], name: string): string {
	const raw = setCookies.find((c) => c.startsWith(`${name}=`));
	if (!raw) throw new Error(`expected Set-Cookie "${name}"`);
	return raw.split(';')[0];
}

/**
 * @proves An administrator still signs in to the console while the IPSIE SL1 profile is on: the console's own
 * application registered no algorithm, so it is signed for PS256, and the console accepts exactly that.
 */
describe('the console under the IPSIE SL1 profile', () => {
	let superAdminId: string;
	let fetchSpy: Mock<typeof fetch> | undefined;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile' });
		await ensureAdminSeed();
		await rootKeys();
		const admin = await getUserStore(ADMIN_BUCKET_ID).create(
			'sl1-root@x.io',
			await Bun.password.hash('correct horse battery')
		);
		await grantSuperAdmin(admin._id);
		superAdminId = admin._id;
	});

	afterEach(() => {
		fetchSpy?.mockRestore();
		fetchSpy = undefined;
	});

	it('signs an administrator in with an ID token signed for PS256', async () => {
		const login = await agent.admin.login.get();
		const oauthCookie = cookiePair(
			login.response.headers.getSetCookie(),
			'admin_oauth'
		);
		const params = new URL(getHeader(login.response, 'location')).searchParams;
		const idToken = await mintAdminIdToken(
			{ sub: superAdminId, nonce: params.get('nonce') ?? undefined },
			{ alg: 'PS256' }
		);
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(
			fetchAnswering(async () =>
				Response.json({ access_token: 'x', id_token: idToken })
			)
		);

		const callback = await agent.admin.callback.get({
			query: {
				code: 'valid-code',
				state: present(params.get('state'), 'a state parameter')
			},
			headers: { cookie: oauthCookie }
		});

		expect(callback.response.headers.getSetCookie().join(';')).toContain(
			'_admin_session='
		);
	});
});
