import {
	describe,
	it,
	expect,
	beforeAll,
	afterEach,
	mock,
	spyOn,
	type Mock
} from 'bun:test';
import { eventBus } from 'lib/event_bus.ts';
import bootstrap, { agent, getHeader, seedJwks } from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { testSigningKeys } from '../jwks/fixtures.ts';
import {
	foreignKey,
	liveKeyByModulus,
	liveSigningKey,
	mintAdminIdToken,
	mintUnsecured,
	mintWithForeignKey,
	tamperPayload
} from './id_token_fixture.ts';

function requiredParam(url: URL, name: string): string {
	const value = url.searchParams.get(name);
	if (value === null)
		throw new Error(`expected the redirect to carry "${name}"`);
	return value;
}

function cookiePair(setCookies: string[], name: string): string {
	const raw = setCookies.find((c) => c.startsWith(`${name}=`));
	if (!raw) throw new Error(`expected Set-Cookie "${name}"`);
	return raw.split(';')[0];
}

type Login = { cookie: string; state: string; nonce: string };

/*
 * Drive the real /admin/login so the binding cookie is genuine, and read the values the server
 * actually asked for rather than assuming them — a case that mints with its own idea of the nonce
 * would pass while proving nothing.
 */
async function startLogin(): Promise<Login> {
	const res = await agent.admin.login.get();
	const url = new URL(getHeader(res.response, 'location'));
	return {
		cookie: cookiePair(res.response.headers.getSetCookie(), 'admin_oauth'),
		state: requiredParam(url, 'state'),
		nonce: requiredParam(url, 'nonce')
	};
}

let fetchSpy: Mock<typeof fetch> | undefined;
let superAdminId: string;

// The loopback exchange can never reach a real server: ISSUER points at a fake host under test. The
// stub returns a genuinely signed token instead of a forged one, which is the whole point.
function stubExchange(body: Record<string, unknown>) {
	fetchSpy = spyOn(globalThis, 'fetch').mockImplementation((async () => ({
		ok: true,
		json: async () => body
	})) as unknown as typeof fetch);
}

async function callback(login: Login, idToken: unknown) {
	stubExchange(
		idToken === undefined
			? { access_token: 'x' }
			: { access_token: 'x', id_token: idToken }
	);
	return agent.admin.callback.get({
		query: { code: 'valid-code', state: login.state },
		headers: { cookie: login.cookie }
	});
}

function sessionCookies(response: Response): string[] {
	return response.headers
		.getSetCookie()
		.filter((c) => c.startsWith(`${ADMIN_SESSION_COOKIE}=`));
}

// Every refusal is the same 401 with the same body, so one assertion covers all of them.
function expectRefused(res: { status: number; response: Response }) {
	expect(res.status).toBe(401);
	expect(sessionCookies(res.response)).toEqual([]);
}

function claims(overrides: Record<string, unknown> = {}, login?: Login) {
	return { sub: superAdminId, nonce: login?.nonce, ...overrides };
}

describe('admin sign-in: ID token verification', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		// Cross-suite isolation: other specs seed the admin store singletons, and findByClientId
		// returns the first match — so drop the cached stores, re-seed, then plant our own super_admin
		// whose _id is the `sub` every minted token carries.
		resetAdminMemoryStores();
		await ensureAdminSeed();
		const superAdmin = await getUserStore(ADMIN_BUCKET_ID).create(
			'verify@x.io',
			await Bun.password.hash('correct horse battery'),
			['super_admin']
		);
		superAdminId = superAdmin._id;
	});

	afterEach(async () => {
		// bun's mock.restore() would wipe beforeAll spies; restore this one explicitly.
		if (fetchSpy) {
			fetchSpy.mockRestore();
			fetchSpy = undefined;
		}
		// Any case that reseeds keys leaves the fixture set behind it.
		await seedJwks(testSigningKeys);
	});

	it('signs in with a genuine token', async () => {
		const login = await startLogin();
		const res = await callback(
			login,
			await mintAdminIdToken(claims({}, login))
		);

		expect(res.status).toBe(302);
		expect(getHeader(res.response, 'location')).toBe('/admin');

		const session = cookiePair(
			res.response.headers.getSetCookie(),
			ADMIN_SESSION_COOKIE
		);
		const me = await agent.admin.api.me.get({ headers: { cookie: session } });
		expect(me.status).toBe(200);
		expect(me.data).toMatchObject({
			roles: ['super_admin'],
			bucketId: ADMIN_BUCKET_ID,
			email: 'verify@x.io'
		});
	});

	it('refuses a token whose payload was edited under its original signature', async () => {
		const login = await startLogin();
		const genuine = await mintAdminIdToken(claims({ sub: 'nobody' }, login));
		expectRefused(
			await callback(login, tamperPayload(genuine, { sub: superAdminId }))
		);
	});

	it('refuses a token signed by a key the server does not hold', async () => {
		const login = await startLogin();
		expectRefused(
			await callback(login, await mintWithForeignKey(claims({}, login)))
		);
	});

	it('refuses a token whose kid names no live key', async () => {
		const login = await startLogin();
		const token = await mintAdminIdToken(claims({}, login), {
			key: foreignKey(),
			kid: 'not-a-live-kid'
		});
		expectRefused(await callback(login, token));
	});

	it('refuses an unsecured token', async () => {
		const login = await startLogin();
		expectRefused(await callback(login, mintUnsecured(claims({}, login))));
	});

	it('refuses a token from another issuer', async () => {
		const login = await startLogin();
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(claims({ iss: 'https://evil.example' }, login))
			)
		);
	});

	it('refuses a token addressed to another client', async () => {
		const login = await startLogin();
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(claims({ aud: 'regular-app' }, login))
			)
		);
	});

	it('refuses an expired token', async () => {
		const login = await startLogin();
		const now = Math.floor(Date.now() / 1000);
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(
					claims({ iat: now - 7200, exp: now - 3600 }, login)
				)
			)
		);
	});

	it('refuses a token issued in the future', async () => {
		const login = await startLogin();
		const now = Math.floor(Date.now() / 1000);
		// `exp` stays valid, so only the issuance instant can be what refuses this one — the case
		// assertPayload skips whenever `exp` is present.
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(
					claims({ iat: now + 3600, exp: now + 7200 }, login)
				)
			)
		);
	});

	it('refuses a token with no subject', async () => {
		const login = await startLogin();
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(claims({ sub: undefined }, login))
			)
		);
	});

	it('refuses a token signed with an algorithm the admin client is not registered for', async () => {
		const login = await startLogin();
		// ES256 is a live key and an advertised server algorithm — but not the admin client's
		// registered id_token_signed_response_alg, which is what the issuer would have used.
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(claims({}, login), { alg: 'ES256' })
			)
		);
	});

	it('refuses a multi-audience token with no azp', async () => {
		const login = await startLogin();
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(
					claims({ aud: ['admin-panel', 'regular-app'] }, login)
				)
			)
		);
	});

	it('refuses a token response carrying no id_token', async () => {
		const login = await startLogin();
		expectRefused(await callback(login, undefined));
	});

	it('refuses an empty id_token', async () => {
		const login = await startLogin();
		expectRefused(await callback(login, ''));
	});

	it('refuses a token with too few segments', async () => {
		const login = await startLogin();
		expectRefused(await callback(login, 'header.payload'));
	});

	it('refuses a token whose header cannot be decoded', async () => {
		const login = await startLogin();
		const genuine = await mintAdminIdToken(claims({}, login));
		const [, payload, signature] = genuine.split('.');
		expectRefused(await callback(login, `!!!!.${payload}.${signature}`));
	});

	it('refuses a token whose payload is not a JSON object', async () => {
		const login = await startLogin();
		const genuine = await mintAdminIdToken(claims({}, login));
		const [header, , signature] = genuine.split('.');
		const scalar = Buffer.from(JSON.stringify('just-a-string')).toString(
			'base64url'
		);
		// Refused at the signature check rather than as malformed — reaching the payload decode with a
		// non-object would require the server's own signing key. Either way: no session.
		expectRefused(await callback(login, `${header}.${scalar}.${signature}`));
	});

	it('does not lock the operator out after a refusal', async () => {
		const refused = await startLogin();
		expectRefused(
			await callback(refused, await mintWithForeignKey(claims({}, refused)))
		);
		if (fetchSpy) {
			fetchSpy.mockRestore();
			fetchSpy = undefined;
		}

		const retry = await startLogin();
		const res = await callback(
			retry,
			await mintAdminIdToken(claims({}, retry))
		);
		expect(res.status).toBe(302);
		expect(sessionCookies(res.response).length).toBe(1);
	});

	it('requests a nonce and binds it to the attempt', async () => {
		const res = await agent.admin.login.get();
		const nonce = requiredParam(
			new URL(getHeader(res.response, 'location')),
			'nonce'
		);
		expect(nonce.length).toBeGreaterThan(20);

		const binding = cookiePair(
			res.response.headers.getSetCookie(),
			'admin_oauth'
		);
		expect(decodeURIComponent(binding)).toContain(nonce);
	});

	it('refuses a token minted for a different sign-in attempt', async () => {
		const attemptA = await startLogin();
		const attemptB = await startLogin();
		expect(attemptA.nonce).not.toBe(attemptB.nonce);

		expectRefused(
			await callback(attemptB, await mintAdminIdToken(claims({}, attemptA)))
		);
	});

	it('refuses a token carrying no nonce', async () => {
		const login = await startLogin();
		expectRefused(
			await callback(
				login,
				await mintAdminIdToken(claims({ nonce: undefined }))
			)
		);
	});

	it('answers two different refusal causes identically', async () => {
		const first = await startLogin();
		const foreign = await callback(
			first,
			await mintWithForeignKey(claims({}, first))
		);
		const foreignBody = JSON.stringify(foreign.error?.value);
		if (fetchSpy) {
			fetchSpy.mockRestore();
			fetchSpy = undefined;
		}

		const second = await startLogin();
		const now = Math.floor(Date.now() / 1000);
		const expired = await callback(
			second,
			await mintAdminIdToken(
				claims({ iat: now - 7200, exp: now - 3600 }, second)
			)
		);

		expect(foreign.status).toBe(expired.status);
		expect(foreignBody).toBe(JSON.stringify(expired.error?.value));
		expect(foreignBody).toBe(
			JSON.stringify({ error: 'invalid_id_token', message: 'login failed' })
		);
	});

	it('leaks neither the token nor the account in a refusal', async () => {
		const login = await startLogin();
		const token = await mintWithForeignKey(claims({}, login));
		const res = await callback(login, token);

		const body = JSON.stringify(res.error?.value);
		for (const segment of token.split('.')) {
			expect(body).not.toContain(segment);
		}
		expect(body).not.toContain(superAdminId);
		expect(body).not.toContain(login.nonce);
	});

	it('reports the failed check on the event bus, and nothing else', async () => {
		const login = await startLogin();
		const observed = mock();
		eventBus.once('admin.login.error', observed);

		expectRefused(
			await callback(login, await mintWithForeignKey(claims({}, login)))
		);

		expect(observed).toHaveBeenCalledTimes(1);
		const payload = observed.mock.calls[0][0];
		expect(Object.keys(payload)).toEqual(['reason']);
		expect(payload).toEqual({ reason: 'signature' });
	});

	it('names the check that failed, per cause', async () => {
		// Each case mints with the attempt's own nonce, so the defect under test is the first thing
		// wrong with the token rather than the nonce.
		const cases: Array<[string, (login: Login) => Promise<unknown>]> = [
			['missing', async () => undefined],
			['malformed', async () => 'header.payload'],
			[
				'algorithm',
				(login) => mintAdminIdToken(claims({}, login), { alg: 'ES256' })
			],
			[
				'issuer',
				(login) =>
					mintAdminIdToken(claims({ iss: 'https://evil.example' }, login))
			],
			[
				'audience',
				(login) => mintAdminIdToken(claims({ aud: 'regular-app' }, login))
			],
			[
				'subject',
				(login) => mintAdminIdToken(claims({ sub: undefined }, login))
			],
			[
				'azp',
				(login) =>
					mintAdminIdToken(claims({ aud: ['admin-panel', 'x'] }, login))
			],
			['nonce', () => mintAdminIdToken(claims({ nonce: 'not-the-one' }))]
		];

		for (const [expectedReason, mint] of cases) {
			const login = await startLogin();
			const observed = mock();
			eventBus.once('admin.login.error', observed);

			expectRefused(await callback(login, await mint(login)));
			expect(observed.mock.calls[0][0]).toEqual({ reason: expectedReason });

			if (fetchSpy) {
				fetchSpy.mockRestore();
				fetchSpy = undefined;
			}
		}
	});

	it('accepts a token signed by a second live RS256 key', async () => {
		const extra = foreignKey();
		await seedJwks([...testSigningKeys, extra]);

		const login = await startLogin();
		// Read the key back out of the live set: seedJwks assigns the RFC 7638 kid, so the token must
		// advertise the kid the server knows it by.
		const seeded = liveKeyByModulus(extra.n);
		const res = await callback(
			login,
			await mintAdminIdToken(claims({}, login), { key: seeded })
		);

		expect(res.status).toBe(302);
		expect(sessionCookies(res.response).length).toBe(1);
	});

	it('refuses a token whose signing key has been retired, and the next sign-in succeeds', async () => {
		const login = await startLogin();
		const retiring = liveSigningKey('RS256');
		const stale = await mintAdminIdToken(claims({}, login), {
			key: retiring
		});

		// Rotate: the RSA key that signed `stale` leaves the live set, a different one takes its place.
		const replacement = foreignKey();
		const [, ec, okp] = testSigningKeys;
		await seedJwks([replacement, ec, okp]);

		expectRefused(await callback(login, stale));
		if (fetchSpy) {
			fetchSpy.mockRestore();
			fetchSpy = undefined;
		}

		const retry = await startLogin();
		const fresh = await mintAdminIdToken(claims({}, retry), {
			key: liveKeyByModulus(replacement.n)
		});
		const res = await callback(retry, fresh);
		expect(res.status).toBe(302);
		expect(sessionCookies(res.response).length).toBe(1);
	});
});
