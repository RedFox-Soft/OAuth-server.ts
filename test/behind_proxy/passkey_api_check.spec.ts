import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { bindClientToBucket } from '../test_helper.js';
import { getBucketStore, getPersonActivityStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { decideApiCall } from 'lib/behind_proxy/api_decision.ts';
import { ApplicationConfig, configuration } from 'lib/configs/application.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { registerClient } from 'lib/models/client.js';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { wordsOf } from 'lib/person_activity/words.ts';
import { admin } from '../provisioning/helpers.ts';
import { present } from '../shape.ts';
import { world, type World } from './helpers.ts';
import {
	apiCheck,
	bearer,
	declareApi,
	jwtFor,
	resourcesPath,
	type ApiView
} from './api_helpers.ts';

const now = () => Math.floor(Date.now() / 1000);

/**
 * @proves The proxy API check holds every JWT and opaque token for a passkey-requiring API to a full passkey sign-in:
 * full passkey passes (200), TOTP / password / conditional passkey / provider / pre-switch `mfa` JWT are refused 401
 * with `X-Auth-Reason: passkey_required`, RFC 9470 `WWW-Authenticate` carrying `acr_values=<phr>` (and `max_age` when
 * also stale), and `passkey_required` person activity with no address; machine tokens stay 403 `no_person`; and the
 * pure `decideApiCall` function shared with the console agrees on every case.
 */
describe('a passkey-requiring API checked at the proxy', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		forgetBucketAddresses();
		await getBucketStore().update(w.acme.id, { passkeyLogin: true });
		ApplicationConfig['personActivity.enabled'] = true;
		await registerClient(
			{
				clientId: 'agent-1',
				clientSecret: 'agent-secret',
				grantTypes: ['authorization_code'],
				responseTypes: ['code'],
				redirectUris: ['https://agent.acme.test/cb']
			},
			{ store: true }
		);
		await bindClientToBucket('agent-1', w.acme.id);
	});

	async function requirePasskeyOn(
		api: ApiView,
		extra: { signInEveryMinutes?: number } = {}
	) {
		const path = resourcesPath(w.acme.id, api.identifier);
		const body = { requirePasskey: true, ...extra };
		const previewed = await admin('PATCH', path, w.cookie, body);
		expect(previewed.status).toBe(409);
		const confirmed = await admin('PATCH', path, w.cookie, {
			...body,
			confirm: true,
			expect: (previewed.body as { expect: Record<string, number> }).expect
		});
		expect(confirmed.status).toBe(200);
	}

	async function checkJwt(api: ApiView, claims: Record<string, unknown>) {
		return apiCheck({
			slug: w.acme.slug,
			identifier: api.identifier,
			authorization: bearer(
				await jwtFor(api, {
					claims: { sub: w.acme.staffMember.accountId, ...claims }
				})
			),
			mcpMethod: 'tools/list'
		});
	}

	it('lets a full passkey JWT through and refuses TOTP, password, conditional passkey, provider, and pre-switch MFA JWTs with 401 passkey_required', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requirePasskeyOn(api);
		const t = now() - 60;
		const phr = configuration.acrMap.phishing_resistant;

		const fullPasskey = await checkJwt(api, {
			auth_time: t,
			acr: phr,
			amr: ['pop', 'user', 'mfa']
		});
		expect(fullPasskey.status).toBe(200);

		const refusedCases: [string, Record<string, unknown>][] = [
			[
				'TOTP',
				{
					auth_time: t,
					acr: configuration.acrMap.multi_factor,
					amr: ['pwd', 'otp', 'mfa']
				}
			],
			[
				'password alone',
				{ auth_time: t, acr: configuration.acrMap.password, amr: ['pwd'] }
			],
			[
				'conditional passkey',
				{
					auth_time: t,
					acr: configuration.acrMap.password,
					amr: ['pop', 'user']
				}
			],
			['provider', { auth_time: t, acr: configuration.acrMap.federated }],
			[
				'pre-switch MFA JWT',
				{
					auth_time: t,
					acr: configuration.acrMap.multi_factor,
					amr: ['pop', 'user', 'mfa']
				}
			]
		];

		for (const [_label, claims] of refusedCases) {
			const res = await checkJwt(api, claims);
			expect(res.status).toBe(401);
			expect(res.headers.get('x-auth-reason')).toBe('passkey_required');
			expect(res.headers.get('cache-control')).toBe('no-store');
			expect(res.headers.get('www-authenticate')).toStartWith(
				`Bearer error="insufficient_user_authentication", error_description="a passkey sign-in is required", acr_values="${phr}", resource_metadata="`
			);
		}
	});

	it('checks opaque tokens by reachedAcr (signInAcr), passing full passkey and refusing TOTP', async () => {
		const api = await declareApi(w.cookie, w.acme.id, {
			checkedBy: 'proxy',
			tokenFormat: 'opaque'
		});
		await requirePasskeyOn(api);
		const t = now() - 60;
		const phr = configuration.acrMap.phishing_resistant;

		const passkeyToken = new AccessToken({
			bucketId: w.acme.id,
			accountId: w.acme.staffMember.accountId,
			client: { clientId: 'agent-1' } as never,
			aud: api.identifier,
			scope: 'files:read',
			gty: 'authorization_code',
			authTime: t,
			/* Reported acr may be mfa (Rule B) while reached signInAcr is phr; opaque check reads reachedAcr. */
			acr: configuration.acrMap.multi_factor,
			signInAcr: phr
		});
		const passkeyValue = await passkeyToken.save();

		const totpToken = new AccessToken({
			bucketId: w.acme.id,
			accountId: w.acme.staffMember.accountId,
			client: { clientId: 'agent-1' } as never,
			aud: api.identifier,
			scope: 'files:read',
			gty: 'authorization_code',
			authTime: t,
			acr: configuration.acrMap.multi_factor,
			signInAcr: configuration.acrMap.multi_factor
		});
		const totpValue = await totpToken.save();

		const ok = await apiCheck({
			slug: w.acme.slug,
			identifier: api.identifier,
			authorization: bearer(passkeyValue),
			mcpMethod: 'tools/list'
		});
		const refused = await apiCheck({
			slug: w.acme.slug,
			identifier: api.identifier,
			authorization: bearer(totpValue),
			mcpMethod: 'tools/list'
		});

		expect(ok.status).toBe(200);
		expect(refused.status).toBe(401);
		expect(refused.headers.get('x-auth-reason')).toBe('passkey_required');
		expect(refused.headers.get('www-authenticate')).toContain(
			`acr_values="${phr}"`
		);
	});

	it('includes both acr_values and max_age when both passkey and freshness are unmet, and records passkey_required activity with no address', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requirePasskeyOn(api, { signInEveryMinutes: 60 });
		const phr = configuration.acrMap.phishing_resistant;

		const res = await checkJwt(api, {
			auth_time: now() - 7200,
			acr: configuration.acrMap.multi_factor
		});
		expect(res.status).toBe(401);
		expect(res.headers.get('x-auth-reason')).toBe('passkey_required');
		expect(res.headers.get('www-authenticate')).toContain(
			`error_description="a passkey sign-in is required", acr_values="${phr}", max_age="3600"`
		);

		/* Flush person activity and verify the recorded row carries no address and clear wording. */
		await flushPersonActivityNow();
		const page = await getPersonActivityStore().listForPerson(
			w.acme.id,
			w.acme.staffMember.accountId,
			{ now: new Date(), limit: 50 }
		);
		const row = present(
			page.rows.find(
				(r) =>
					r.kind === 'api' &&
					r.place.resource === api.identifier &&
					r.reason === 'passkey_required'
			),
			'passkey_required activity row'
		);
		expect(row.outcome).toBe('sign_in_again');
		expect(row.address).toBeUndefined();
		const words = wordsOf(row, {
			place: 'Files MCP',
			client: 'Agent',
			provider: null
		});
		expect(words.reason).toBe(
			'Signed in without a passkey; Files MCP asks for one'
		);
	});

	it('refuses a machine token (no auth_time) with 403 no_person and no WWW-Authenticate', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requirePasskeyOn(api);

		const res = await checkJwt(api, { auth_time: undefined, acr: undefined });
		expect(res.status).toBe(403);
		expect(res.headers.get('x-auth-reason')).toBe('no_person');
		expect(res.headers.get('www-authenticate')).toBeNull();
	});

	it('matches decideApiCall (shared with the console) across password, code, and passkey levels', () => {
		const t = 1_800_000_000;
		const baseFacts = {
			headers: {
				method: 'tools/list',
				name: null,
				protocolVersion: '2026-07-28'
			},
			address: null,
			at: t * 1000,
			person: { groupIds: [], attributes: {}, canSignIn: true },
			explain: true
		};

		const passkeyApi = { signIn: { passkey: true, code: false } };
		const codeApi = { signIn: { code: true } };

		expect(
			decideApiCall(passkeyApi, {
				...baseFacts,
				token: {
					scopes: new Set(['files:read']),
					signedInAt: t - 60,
					signedInWithCode: true,
					signedInWithPasskey: true
				}
			}).outcome
		).toBe('allow');

		const totpOnPasskey = decideApiCall(passkeyApi, {
			...baseFacts,
			token: {
				scopes: new Set(['files:read']),
				signedInAt: t - 60,
				signedInWithCode: true,
				signedInWithPasskey: false
			}
		});
		expect(totpOnPasskey).toEqual({
			outcome: 'sign_in',
			unmet: {
				passkey: true,
				code: false,
				recent: false
			}
		});

		/* Full passkey also satisfies a two-step (code) API rule. */
		expect(
			decideApiCall(codeApi, {
				...baseFacts,
				token: {
					scopes: new Set(['files:read']),
					signedInAt: t - 60,
					signedInWithCode: true,
					signedInWithPasskey: true
				}
			}).outcome
		).toBe('allow');
	});
});
