import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn,
	type Mock
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { getHeader } from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getBucketStore,
	getPasskeyStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID
} from 'lib/admin/consts.ts';
import { createAdminSession } from 'lib/admin/auth/session.ts';
import { grantSuperAdmin } from 'lib/admin/super_admins.ts';
import { ApplicationConfig, configuration } from 'lib/configs/application.ts';
import { ADMIN_REQUEST_BUCKET } from 'lib/configs/issuer.ts';
import { MIGRATIONS } from 'lib/consts/migrations.ts';
import { sessionCookieName } from 'lib/consts/param_list.ts';
import { eventBus } from 'lib/event_bus.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { checksumOf, compare } from 'lib/migrations/state.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { Grant } from 'lib/models/grant.ts';
import { RefreshToken } from 'lib/models/refresh_token.ts';
import { Session } from 'lib/models/session.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { rpIdFor } from 'lib/passkeys/relying_party.ts';
import { mintAdminIdToken } from './id_token_fixture.ts';
import { fetchAnswering } from 'test/fetch_mock.ts';
import { present, shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { call as tool, rpc } from '../mcp/rpc.ts';
import {
	Browser,
	PASSWORD,
	mailOn,
	person,
	seedPasskey
} from '../passkeys/helpers.ts';

function cookiePair(setCookies: string[], name: string): string {
	const raw = setCookies.find((c) => c.startsWith(`${name}=`));
	if (!raw) throw new Error(`expected Set-Cookie "${name}"`);
	return raw.split(';')[0];
}

async function adminRequest(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<{
	status: number;
	body: Record<string, unknown>;
	response: Response;
}> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				...(body === undefined ? {} : { 'content-type': 'application/json' }),
				cookie
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	let parsed: Record<string, unknown> = {};
	try {
		if (text) parsed = JSON.parse(text) as Record<string, unknown>;
	} catch {
		parsed = { raw: text };
	}
	return { status: response.status, body: parsed, response };
}

async function sessionCookieFor(
	userId: string,
	signInAcr: string | null = configuration.acrMap.password,
	signInAmr: string[] = ['pwd']
): Promise<string> {
	const session = await createAdminSession({
		userId,
		bucketId: ADMIN_BUCKET_ID,
		signedInWith: null,
		signInAcr,
		signInAmr,
		signInAt: epochTime(),
		tokens: { accessToken: 'test-token' }
	});
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

let rpcSeq = 0;

async function mcpTokenFor(
	accountId: string,
	signInAcr: string
): Promise<string> {
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId,
		scope: 'openid',
		acr: signInAcr,
		signInAcr
	});
	at.setAudience(MCP_RESOURCE);
	return at.save();
}

const PreviewShape = Type.Object({
	confirmationRequired: Type.Literal(true),
	changes: Type.Array(Type.String()),
	consequences: Type.Array(Type.String()),
	expect: Type.Record(Type.String(), Type.Number())
});

/**
 * @proves Requiring a passkey for console sign-in enforces self-proof preconditions and named colleague preview,
 * gates /admin/login, /admin/callback, live console sessions, /mcp authorization/token/refresh/live calls, renders a
 * strict refusal page with no passkey creation on Administrators, protects console reachability across every entry
 * point, and declares the 2026-11-27-admin-passkeys-fence migration.
 */
describe('console passkey requirement and reachability protection', () => {
	let fetchSpy: Mock<typeof fetch> | undefined;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
		ApplicationConfig['mcp.enabled'] = true;
		await mailOn();
	});

	afterEach(() => {
		if (fetchSpy) {
			fetchSpy.mockRestore();
			fetchSpy = undefined;
		}
	});

	it('refuses consolePasskeyRequired on non-admin projects (422) and enforces preconditions + named preview on Administrators', async () => {
		const superAdmin = await createAdministrator('super', 'super@x.io');
		const colleague = await createAdministrator('plain', 'no-key@x.io');
		const passCookie = await sessionCookieFor(
			superAdmin._id,
			configuration.acrMap.password,
			['pwd']
		);

		/* 422 on non-admin project. */
		const onDefault = await adminRequest(
			'PATCH',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}`,
			passCookie,
			{ consolePasskeyRequired: true }
		);
		expect(onDefault.status).toBe(422);
		expect(onDefault.body.field).toBe('consolePasskeyRequired');

		/* 409 passkeys_not_accepted when passkeyLogin is off. */
		const whenOff = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			passCookie,
			{ consolePasskeyRequired: true }
		);
		expect(whenOff.status).toBe(409);
		expect(whenOff.body.code).toBe('passkeys_not_accepted');

		/* Turn passkeys on, still refused because caller holds no working passkey. */
		await getBucketStore().update(ADMIN_BUCKET_ID, { passkeyLogin: true });
		const noPasskey = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			passCookie,
			{ consolePasskeyRequired: true }
		);
		expect(noPasskey.status).toBe(409);

		/* Seed a working passkey for superAdmin, still refused from a password session. */
		const adminBucket = present(
			await getBucketStore().find(ADMIN_BUCKET_ID),
			'admin bucket'
		);
		await seedPasskey(ADMIN_BUCKET_ID, superAdmin._id, {
			rpId: rpIdFor(adminBucket),
			createdVia: 'password_code'
		});
		const notPasskeySession = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			passCookie,
			{ consolePasskeyRequired: true }
		);
		expect(notPasskeySession.status).toBe(409);

		/* From a passkey session: returns preview naming colleague without a passkey. */
		const phrCookie = await sessionCookieFor(
			superAdmin._id,
			configuration.acrMap.phishing_resistant,
			['pop', 'user', 'mfa']
		);
		const previewRes = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			phrCookie,
			{ consolePasskeyRequired: true }
		);
		expect(previewRes.status).toBe(409);
		const preview = shaped(PreviewShape, previewRes.body);
		expect(preview.changes).toContain('consolePasskeyOn');
		expect(preview.expect.withoutPasskey).toBe(1);
		expect(preview.consequences.join(' ')).toContain(colleague.email);

		/* Stale expect is refused. */
		const stale = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			phrCookie,
			{
				consolePasskeyRequired: true,
				confirm: true,
				expect: { withoutPasskey: 0 }
			}
		);
		expect(stale.status).toBe(409);

		/* Matching expect saves. */
		const saved = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			phrCookie,
			{
				consolePasskeyRequired: true,
				confirm: true,
				expect: preview.expect
			}
		);
		expect(saved.status).toBe(200);
		expect(saved.body.consolePasskeyRequired).toBe(true);
	});

	it('enforces consolePasskeyRequired on /admin/login, /admin/callback, live console sessions, and /mcp (live + refresh before rotation)', async () => {
		const superAdmin = await createAdministrator('super', 'root@x.io');
		const adminBucket = present(
			await getBucketStore().find(ADMIN_BUCKET_ID),
			'admin bucket'
		);
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			passkeyLogin: true,
			consolePasskeyRequired: true
		});
		await seedPasskey(ADMIN_BUCKET_ID, superAdmin._id, {
			rpId: rpIdFor(adminBucket),
			createdVia: 'password_code'
		});

		/* /admin/login requests acr_values=phr (and ?reauth=1 adds prompt=login). */
		const loginRes = await elysia.handle(
			new Request('http://e.ly/admin/login?reauth=1')
		);
		expect(loginRes.status).toBe(302);
		const authUrl = new URL(getHeader(loginRes, 'location'));
		expect(authUrl.searchParams.get('acr_values')).toBe(
			configuration.acrMap.phishing_resistant
		);
		expect(authUrl.searchParams.get('prompt')).toBe('login');

		const oauthCookie = cookiePair(
			loginRes.headers.getSetCookie(),
			'admin_oauth'
		);
		const state = present(authUrl.searchParams.get('state'), 'state');
		const nonce = present(authUrl.searchParams.get('nonce'), 'nonce');

		/* /admin/callback refuses a valid ID token with acr=mfa (constant 401 + event bus reason 'acr'). */
		const reasons: string[] = [];
		const listener = (payload: { reason: string }) => {
			reasons.push(payload.reason);
		};
		eventBus.on('admin.login.error', listener);
		try {
			const weakIdToken = await mintAdminIdToken({
				sub: superAdmin._id,
				nonce,
				acr: configuration.acrMap.multi_factor
			});
			fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(
				fetchAnswering(async () =>
					Response.json({ access_token: 'x', id_token: weakIdToken })
				)
			);
			const weakCb = await elysia.handle(
				new Request(
					`http://e.ly/admin/callback?code=c1&state=${encodeURIComponent(state)}`,
					{ headers: { cookie: oauthCookie } }
				)
			);
			expect(weakCb.status).toBe(401);
			expect(await weakCb.json()).toEqual({
				error: 'invalid_id_token',
				message: 'login failed'
			});
			expect(reasons).toContain('acr');
		} finally {
			eventBus.off('admin.login.error', listener);
		}

		/* /admin/callback accepts an ID token with acr=phr. */
		const loginRes2 = await elysia.handle(
			new Request('http://e.ly/admin/login')
		);
		const oauthCookie2 = cookiePair(
			loginRes2.headers.getSetCookie(),
			'admin_oauth'
		);
		const authUrl2 = new URL(getHeader(loginRes2, 'location'));
		const strongIdToken = await mintAdminIdToken({
			sub: superAdmin._id,
			nonce: present(authUrl2.searchParams.get('nonce'), 'nonce2'),
			acr: configuration.acrMap.phishing_resistant
		});
		fetchSpy.mockRestore();
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(
			fetchAnswering(async () =>
				Response.json({ access_token: 'x', id_token: strongIdToken })
			)
		);
		const strongCb = await elysia.handle(
			new Request(
				`http://e.ly/admin/callback?code=c2&state=${encodeURIComponent(present(authUrl2.searchParams.get('state'), 'state2'))}`,
				{ headers: { cookie: oauthCookie2 } }
			)
		);
		expect(strongCb.status).toBe(302);
		const livePhrCookie = cookiePair(
			strongCb.headers.getSetCookie(),
			ADMIN_SESSION_COOKIE
		);

		/* Live console sessions: non-passkey session immediately refused (401 API, 302 page); passkey session works. */
		const stalePasswordCookie = await sessionCookieFor(
			superAdmin._id,
			configuration.acrMap.password,
			['pwd']
		);
		expect(
			(await adminRequest('GET', '/admin/api/me', stalePasswordCookie)).status
		).toBe(401);
		const pageRedirect = await elysia.handle(
			new Request('http://e.ly/admin', {
				headers: { cookie: stalePasswordCookie }
			})
		);
		expect(pageRedirect.status).toBe(302);
		expect(pageRedirect.headers.get('location')).toContain('/admin/login');
		expect(
			(await adminRequest('GET', '/admin/api/me', livePhrCookie)).status
		).toBe(200);

		/* Live /mcp tokens: non-passkey token refused 401 with reason 'passkey_required'; passkey token works. */
		const mcpReasons: string[] = [];
		const mcpListener = (payload: { reason: string }) => {
			mcpReasons.push(payload.reason);
		};
		eventBus.on('mcp.auth.error', mcpListener);
		try {
			const weakMcpToken = await mcpTokenFor(
				superAdmin._id,
				configuration.acrMap.multi_factor
			);
			const weakMcpResp = await elysia.handle(
				new Request('http://e.ly/mcp', {
					method: 'POST',
					headers: {
						authorization: `Bearer ${weakMcpToken}`,
						'content-type': 'application/json',
						accept: 'application/json, text/event-stream'
					},
					body: JSON.stringify({
						jsonrpc: '2.0',
						id: ++rpcSeq,
						method: 'initialize',
						params: {
							protocolVersion: '2026-07-28',
							capabilities: {},
							clientInfo: { name: 't', version: '1' }
						}
					})
				})
			);
			expect(weakMcpResp.status).toBe(401);
			expect(mcpReasons).toContain('passkey_required');
		} finally {
			eventBus.off('mcp.auth.error', mcpListener);
		}

		const strongMcpToken = await mcpTokenFor(
			superAdmin._id,
			configuration.acrMap.phishing_resistant
		);
		const initStrong = await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcSeq,
				method: 'initialize',
				params: {
					protocolVersion: '2026-07-28',
					capabilities: {},
					clientInfo: { name: 't', version: '1' }
				}
			},
			strongMcpToken
		);
		expect(initStrong.error).toBeUndefined();
		const who = await rpc(tool('whoami', {}), strongMcpToken);
		expect(who.result?.isError).not.toBe(true);

		/* /mcp refresh token from a non-passkey sign-in is refused BEFORE rotation. */
		const mcpClient = await Client.find(ADMIN_MCP_CLIENT_ID);
		const grant = new Grant({
			accountId: superAdmin._id,
			clientId: ADMIN_MCP_CLIENT_ID
		});
		grant.addOIDCScope('openid offline_access');
		grant.addResourceScope(MCP_RESOURCE, 'openid');
		const grantId = await grant.save();

		const weakRt = new RefreshToken({
			accountId: superAdmin._id,
			client: mcpClient,
			grantId,
			gty: 'authorization_code',
			scope: 'openid offline_access',
			resource: MCP_RESOURCE,
			acr: configuration.acrMap.multi_factor,
			signInAcr: configuration.acrMap.multi_factor,
			authTime: epochTime()
		});
		const weakRtValue = await weakRt.save();

		const refreshWeak = await elysia.handle(
			new Request('http://e.ly/token', {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'refresh_token',
					client_id: ADMIN_MCP_CLIENT_ID,
					refresh_token: weakRtValue,
					resource: MCP_RESOURCE
				})
			})
		);
		expect(refreshWeak.status).toBe(400);
		expect(((await refreshWeak.json()) as { error?: string }).error).toBe(
			'invalid_grant'
		);
		/* Still unconsumed (not rotated). */
		expect(
			Boolean((await RefreshToken.tryFind(weakRtValue))?.payload.consumed)
		).toBe(false);

		/* Passkey refresh token succeeds. */
		const strongRt = new RefreshToken({
			accountId: superAdmin._id,
			client: mcpClient,
			grantId,
			gty: 'authorization_code',
			scope: 'openid offline_access',
			resource: MCP_RESOURCE,
			acr: configuration.acrMap.phishing_resistant,
			signInAcr: configuration.acrMap.phishing_resistant,
			authTime: epochTime()
		});
		const strongRtValue = await strongRt.save();
		const refreshStrong = await elysia.handle(
			new Request('http://e.ly/token', {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'refresh_token',
					client_id: ADMIN_MCP_CLIENT_ID,
					refresh_token: strongRtValue,
					resource: MCP_RESOURCE
				})
			})
		);
		expect(refreshStrong.status).toBe(200);
	});

	it('never silently reuses a password+TOTP session for console login and never offers passkey creation on the refusal page', async () => {
		const { email, accountId } = await person(ADMIN_BUCKET_ID);
		await grantSuperAdmin(accountId);
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			passkeyLogin: true,
			consolePasskeyRequired: true
		});

		/* Plant a live Administrators provider session signed in with password + TOTP (not passkey). */
		const providerSession = new Session({
			accountId,
			acr: configuration.acrMap.multi_factor,
			amr: ['pwd', 'otp', 'mfa'],
			loginTs: epochTime()
		});
		const sessionId = await providerSession.save(3600);
		const cookie = `${sessionCookieName(ADMIN_REQUEST_BUCKET)}=${sessionId}`;

		const authUrl = `http://e.ly/auth?client_id=${ADMIN_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent('http://e.ly/admin/callback')}&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`;
		const authRes = await elysia.handle(
			new Request(authUrl, { headers: { cookie } })
		);
		expect(authRes.status).toBe(303);
		const loc = present(
			authRes.headers.get('location'),
			'interaction redirect'
		);
		/* Existing password+TOTP session MUST NOT silently issue a code; it lands on /ui/:uid/login. */
		expect(loc).toMatch(/^\/ui\/[^/]+\/login$/);

		/* Submitting password on that login page reaches the passkey refusal page with passkeyAsk (NEVER passkeyCreate). */
		const browser = new Browser('http://e.ly');
		const loginPage = await browser.open(authUrl);
		expect(loginPage.url).toMatch(/\/ui\/[^/]+\/login$/);
		const posted = await browser.post(loginPage.url, {
			username: email,
			password: PASSWORD
		});
		expect(posted.status).toBe(303);
		const afterPost = await browser.open(
			new URL(
				present(posted.headers.get('location'), 'resume redirect'),
				loginPage.url
			).toString()
		);
		expect(afterPost.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		const html = await afterPost.response.text();
		expect(html).toContain('passkeyAsk');
		expect(html).not.toContain('passkeyCreate');
	});

	it('protects console reachability across passkey turn-off, personal remove, super-admin revoke, disown, deactivate, and super-admin withdraw', async () => {
		const super1 = await createAdministrator('super', 'super1@x.io');
		const super2 = await createAdministrator('super', 'super2@x.io');
		await getUserStore(ADMIN_BUCKET_ID).update(super1._id, { verified: true });
		await getUserStore(ADMIN_BUCKET_ID).update(super2._id, { verified: true });
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			passkeyLogin: true,
			consolePasskeyRequired: true
		});
		const adminBucket = present(
			await getBucketStore().find(ADMIN_BUCKET_ID),
			'admin bucket'
		);
		const pk1 = await seedPasskey(ADMIN_BUCKET_ID, super1._id, {
			rpId: rpIdFor(adminBucket),
			createdVia: 'password_code'
		});
		const cookie1 = await sessionCookieFor(
			super1._id,
			configuration.acrMap.phishing_resistant,
			['pop', 'user', 'mfa']
		);
		const cookie2 = await sessionCookieFor(
			super2._id,
			configuration.acrMap.phishing_resistant,
			['pop', 'user', 'mfa']
		);

		/* Turning passkeyLogin off while consolePasskeyRequired stays on → 409. */
		expect(
			(
				await adminRequest(
					'PATCH',
					`/admin/api/projects/${ADMIN_BUCKET_ID}`,
					cookie1,
					{ passkeyLogin: false }
				)
			).status
		).toBe(409);

		/* Super1 removing own only passkey → 409 (last way in & reachability). */
		expect(
			(
				await adminRequest(
					'DELETE',
					`/admin/api/me/passkeys/${pk1._id}`,
					cookie1
				)
			).status
		).toBe(409);

		/* Super2 revoking super1's only working passkey while super2 holds none → 409. */
		expect(
			(
				await adminRequest(
					'DELETE',
					`/admin/api/admins/${super1._id}/passkeys/${pk1._id}`,
					cookie2
				)
			).status
		).toBe(409);

		/* Deactivating or withdrawing super-admin from super1 while super2 holds no passkey → 409. */
		expect(
			(await adminRequest('DELETE', `/admin/api/admins/${super1._id}`, cookie2))
				.status
		).toBe(409);
		expect(
			(
				await adminRequest(
					'DELETE',
					`/admin/api/admins/${super1._id}/super-admin`,
					cookie2
				)
			).status
		).toBe(409);

		/* Once super2 also holds a working passkey, revoking super1's passkey succeeds! */
		await seedPasskey(ADMIN_BUCKET_ID, super2._id, {
			rpId: rpIdFor(adminBucket),
			createdVia: 'password_code'
		});
		const revoked = await adminRequest(
			'DELETE',
			`/admin/api/admins/${super1._id}/passkeys/${pk1._id}`,
			cookie2
		);
		expect(revoked.status).toBe(200);
		expect(await getPasskeyStore().countOf(ADMIN_BUCKET_ID, super1._id)).toBe(
			0
		);

		/* When consolePasskeyRequired is off & passwordLogin is off with no providers, super2's passkey keeps console reachable,
		   so turning passkeyLogin off is still refused 409. */
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			consolePasskeyRequired: false,
			passwordLogin: false,
			federation: []
		});
		const turnOffBlocked = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			cookie2,
			{ passkeyLogin: false }
		);
		expect(turnOffBlocked.status).toBe(409);

		/* Re-grant check: unused import guard for grantSuperAdmin. */
		await grantSuperAdmin(super1._id);
		expect(await adminSessionStore.find('nonexistent')).toBeNull();
	});

	it('declares 2026-11-27-admin-passkeys-fence and makes an older release report ahead', async () => {
		const fence = MIGRATIONS.find(
			(m) => m.id === '2026-11-27-admin-passkeys-fence'
		);
		expect(fence).toBeDefined();
		const applied = MIGRATIONS.map((m) => ({
			id: m.id,
			checksum: checksumOf(m),
			appliedAt: new Date()
		}));
		const older = MIGRATIONS.filter(
			(m) => m.id !== '2026-11-27-admin-passkeys-fence'
		);
		const plan = compare(older, applied);
		expect(plan.status).toBe('ahead');
		if (plan.status === 'ahead') {
			expect(plan.unknown).toContain('2026-11-27-admin-passkeys-fence');
		}
	});
});
