import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

const PASSWORD = 'correct horse battery';

/*
 * One browser's cookie jar, kept by hand because these cases are about *which* cookies a flow reads
 * back — an Eden client that carried them for us would hide the very thing under test. `Set-Cookie`
 * arrives as one folded header, and a comma inside an `Expires` date is not a separator, so the split
 * looks ahead for the start of a cookie pair.
 */
function accept(
	jar: Map<string, string>,
	response: Response
): Map<string, string> {
	const folded = response.headers.get('set-cookie');
	if (!folded) return jar;
	for (const one of folded.split(/,(?=\s*[A-Za-z0-9_-]+=)/)) {
		const [name, value] = one.split(';')[0].trim().split('=');
		if (value) jar.set(name, value);
		else jar.delete(name);
	}
	return jar;
}

const header = (jar: Map<string, string>) =>
	[...jar].map(([name, value]) => `${name}=${value}`).join('; ');

async function startLogin(clientId: string, jar: Map<string, string>) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie: header(jar) }
	});
	accept(jar, response);
	return getHeader(response, 'location');
}

async function signIn(
	clientId: string,
	username: string,
	jar: Map<string, string>
) {
	const uid = (await startLogin(clientId, jar)).split('/')[2];
	const { response } = await agent
		.ui({ uid })
		.login.post(
			{ username, password: PASSWORD },
			{ headers: { cookie: header(jar) } }
		);
	accept(jar, response);
	return response.status;
}

/**
 * @proves A sign-in is carried by the session of the bucket the client signs into, so an
 * administrator signs in whatever else the browser already holds and is not asked twice.
 */
describe('console session bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
		await getUserStore(ADMIN_BUCKET_ID).create(
			'admin-only@x.io',
			await Bun.password.hash(PASSWORD),
			['project_admin']
		);
		await getUserStore().create(
			'default-only@x.io',
			await Bun.password.hash(PASSWORD)
		);
	});

	it('signs an administrator in when the browser already holds another bucket’s sign-in', async () => {
		const jar = new Map<string, string>();
		expect(await signIn('regular-app', 'default-only@x.io', jar)).toBe(303);

		expect(await signIn('admin-panel', 'admin-only@x.io', jar)).toBe(303);
	});

	it('does not ask for the password again once the administrator is signed in', async () => {
		const jar = new Map<string, string>();
		expect(await signIn('admin-panel', 'admin-only@x.io', jar)).toBe(303);

		expect(await startLogin('admin-panel', jar)).not.toMatch(/\/login$/);
	});
});
