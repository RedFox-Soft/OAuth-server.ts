import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	spyOn,
	mock,
	expect,
	setSystemTime
} from 'bun:test';
import {
	SignJWT,
	exportJWK,
	generateKeyPair,
	type GenerateKeyPairResult
} from 'jose';

import bootstrap, {
	agent,
	getHeader,
	type Setup,
	redirectParameter
} from '../test_helper.js';
import nanoid from '../../lib/helpers/nanoid.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { ISSUER } from 'lib/configs/env.js';
import { ttl } from 'lib/configs/liveTime.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';

const DAY = 24 * 60 * 60;
const REFRESH_LIFETIME = 14 * DAY;

async function proof(keypair: GenerateKeyPairResult) {
	return new SignJWT({ htu: `${ISSUER}/token`, htm: 'POST' })
		.setProtectedHeader({
			alg: 'ES256',
			typ: 'dpop+jwt',
			jwk: await exportJWK(keypair.publicKey)
		})
		.setJti(nanoid())
		.setIssuedAt()
		.sign(keypair.privateKey);
}

/**
 * @proves A browser application's refresh-token chain ends when its first token would have expired,
 * however often it is rotated; a confidential or key-bound chain gets a full lifetime on rotation.
 */
describe('a browser application refreshing its tokens', () => {
	let setup: Setup;
	let t0: number;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'browser_chain' });
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		/*
		 * The condition under which the bound matters. A grant fixes its expiry when first saved and
		 * refresh refuses an expired grant, so with default lifetimes the grant would end the chain at
		 * the same moment and hide whether the refresh token's own bound holds.
		 */
		spyOn(ttl, 'Grant').mockReturnValue(365 * DAY);
		t0 = Date.now();
	});

	afterEach(() => {
		setSystemTime();
		mock.restore();
	});

	async function refreshTokenFor(
		clientId: string,
		redirectUri: string,
		dpop?: string
	) {
		const authReq = new AuthorizationRequest({
			client_id: clientId,
			scope: 'openid offline_access',
			prompt: 'consent',
			redirect_uri: redirectUri
		});
		const cookie = await setup.login({ scope: 'openid offline_access' });
		const auth = await agent.auth.get({
			query: authReq.params,
			headers: { cookie }
		});
		const code = redirectParameter(auth.response, 'code');
		const { data } = await authReq.getToken(code, {
			headers: dpop ? { dpop } : {}
		});
		return rotatedFrom(data);
	}

	function refresh(
		refreshToken: string,
		{ clientId = 'spa', dpop }: { clientId?: string; dpop?: string } = {}
	) {
		const confidential = clientId === 'backend';
		return agent.token.post(
			{
				grant_type: 'refresh_token',
				refresh_token: refreshToken,
				...(confidential ? {} : { client_id: clientId })
			},
			{
				headers: {
					...(confidential
						? AuthorizationRequest.basicAuthHeader('backend', 'secret')
						: {}),
					...(dpop ? { dpop } : {})
				}
			}
		);
	}

	/* The token response's refresh token; the response union also covers the error shapes. */
	function rotatedFrom(data: unknown): string {
		// The union of success and error bodies has no common `refresh_token`; checked at runtime below.
		const value = (data as { refresh_token?: unknown } | null)?.refresh_token;
		if (typeof value !== 'string') throw new Error('expected a refresh token');
		return value;
	}

	function expiryOf(refreshToken: string): number {
		return TestAdapter.for('RefreshToken').syncFind(
			setup.getTokenJti(refreshToken)
		).exp;
	}

	function at(days: number, seconds = 0) {
		setSystemTime(new Date(t0 + (days * DAY + seconds) * 1000));
	}

	/*
	 * Read from the store rather than from a response: a public client cannot introspect, and no
	 * response it receives states its refresh token's expiry — the refusal case below is the half of
	 * this invariant a client can observe.
	 */
	it('receives a rotated refresh token that expires when the first token of its chain would have', async () => {
		const first = await refreshTokenFor('spa', 'https://spa.example.com/cb');
		const issuedAt = Math.floor(t0 / 1000);

		at(10);
		const { data, status } = await refresh(first);
		expect(status).toBe(200);
		expect(
			Math.abs(expiryOf(rotatedFrom(data)) - (issuedAt + REFRESH_LIFETIME))
		).toBeLessThanOrEqual(2);
	});

	it("is refused as invalid_grant once the first token's lifetime has passed, however often it rotated", async () => {
		let current = await refreshTokenFor('spa', 'https://spa.example.com/cb');

		for (const day of [5, 10]) {
			at(day);
			const { data, status } = await refresh(current);
			expect(status).toBe(200);
			current = rotatedFrom(data);
		}

		at(14, 5);
		const { error } = await refresh(current);
		if (!error) throw new Error('expected a refusal');
		expect(Number(error.status)).toBe(400);
		expect(error.value).toHaveProperty('error', 'invalid_grant');
	});

	it('a confidential client receives a full lifetime when its refresh token rotates', async () => {
		const first = await refreshTokenFor(
			'backend',
			'https://backend.example.com/cb'
		);

		at(11);
		const { data, status } = await refresh(first, { clientId: 'backend' });
		expect(status).toBe(200);
		const now = Math.floor(Date.now() / 1000);
		expect(
			Math.abs(expiryOf(rotatedFrom(data)) - (now + REFRESH_LIFETIME))
		).toBeLessThanOrEqual(2);
	});

	it('a browser application whose refresh token is DPoP-bound receives a full lifetime when it rotates', async () => {
		const keypair = await generateKeyPair('ES256', { extractable: true });
		const first = await refreshTokenFor(
			'spa',
			'https://spa.example.com/cb',
			await proof(keypair)
		);

		at(11);
		const { data, status } = await refresh(first, {
			dpop: await proof(keypair)
		});
		expect(status).toBe(200);
		const now = Math.floor(Date.now() / 1000);
		expect(
			Math.abs(expiryOf(rotatedFrom(data)) - (now + REFRESH_LIFETIME))
		).toBeLessThanOrEqual(2);
	});
});
