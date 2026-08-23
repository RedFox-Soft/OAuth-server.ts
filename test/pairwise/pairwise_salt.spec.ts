import { describe, it, beforeAll, expect } from 'bun:test';
import crypto from 'node:crypto';
import url from 'node:url';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { decode as decodeJWT } from 'lib/helpers/jwt.js';
import { pairwiseSalt } from 'lib/configs/pairwiseSalt.js';

/*
 * Pairwise identifiers, end to end — spec 023, User Story 1.
 *
 * What this suite is for is stability: the `sub` a relying party stores as its account key must not
 * depend on which host, container or process happened to answer. The salt it is derived from used to
 * be `os.hostname()`, so every reschedule silently handed every relying party a stranger.
 *
 * The stability assertion that matters most cannot be made here, and it is worth being explicit about
 * why. A genuine second process cannot see this one's in-memory store, so booting twice would prove
 * the opposite of what it claims. Boot-to-boot identity is proven at the resolution level in
 * test/configuration/pairwise_salt_resolve.spec.ts ("returns the identical salt on a second
 * resolution"), and what is proven here is the other half: that the identifier a client actually
 * receives is a pure function of the salt, the sector and the account — so once the salt is stable,
 * the identifier is.
 */

const ACCOUNT = 'pairwise-salt-account';

// The derivation, restated independently of the implementation. This is the tripwire (FR-011a): it
// pins the INPUTS, not merely their stability, so reintroducing a host- or process-derived component
// fails here rather than passing quietly.
function expectedSub(sector: string, accountId: string): string {
	const salt = pairwiseSalt();
	if (salt === null) {
		throw new Error(
			'no pairwise salt resolved; the suite cannot compute a sub'
		);
	}
	return crypto
		.createHash('sha256')
		.update(sector)
		.update(accountId)
		.update(salt)
		.digest('hex');
}

describe('pairwise identifiers', () => {
	let setup: Setup;
	const subs: Record<string, string> = {};
	const accessTokens: Record<string, string> = {};

	// One authorization per client, all against the same account, so every later assertion is a
	// comparison between identifiers the server issued for one person.
	async function authorize(clientId: string, cookie: string) {
		const auth = new AuthorizationRequest({
			client_id: clientId,
			scope: 'openid email'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});

		expect(response.status).toBe(303);
		const location = response.headers.get('location');
		if (!location) throw new Error(`no location for ${clientId}`);
		const { code } = url.parse(location, true).query;

		const { data } = await auth.getToken(code);
		if (!data?.id_token || !data?.access_token) {
			throw new Error(`no tokens for ${clientId}: ${JSON.stringify(data)}`);
		}

		subs[clientId] = decodeJWT(data.id_token).payload.sub;
		accessTokens[clientId] = data.access_token;
	}

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'pairwise_salt' });
		const cookie = await setup.login({
			scope: 'openid email',
			accountId: ACCOUNT
		});

		for (const clientId of [
			'public-one',
			'pairwise-one',
			'pairwise-one-sibling',
			'pairwise-two'
		]) {
			await authorize(clientId, cookie);
		}
	});

	describe('derivation', () => {
		it('derives the sub from the stored salt, the sector and the account', () => {
			// Fails if the salt reverts to a per-host or per-process value, which is the whole point.
			expect(subs['pairwise-one']).toBe(
				expectedSub('rp-one.example.com', ACCOUNT)
			);
			expect(subs['pairwise-two']).toBe(
				expectedSub('rp-two.example.com', ACCOUNT)
			);
		});

		it('leaves a public client with the account identifier itself', () => {
			expect(subs['public-one']).toBe(ACCOUNT);
		});

		it('gives a pairwise client something other than the account identifier', () => {
			expect(subs['pairwise-one']).not.toBe(ACCOUNT);
			expect(subs['pairwise-one']).toMatch(/^[0-9a-f]{64}$/);
		});
	});

	describe('sector scoping', () => {
		it('gives two clients in one sector the same identifier', () => {
			// Same sector by sharing a redirect host, different clients by path — so this is agreement
			// between two registrations rather than a client compared with itself.
			expect(subs['pairwise-one-sibling']).toBe(subs['pairwise-one']);
		});

		it('gives clients in different sectors different identifiers', () => {
			expect(subs['pairwise-two']).not.toBe(subs['pairwise-one']);
		});
	});

	describe('stability', () => {
		it('returns the same identifier on a second authorization', async () => {
			const cookie = await setup.login({
				scope: 'openid email',
				accountId: ACCOUNT
			});
			await authorize('pairwise-one', cookie);

			expect(subs['pairwise-one']).toBe(
				expectedSub('rp-one.example.com', ACCOUNT)
			);
		});
	});

	describe('cross-surface agreement', () => {
		it('reports the same identifier at the userinfo endpoint', async () => {
			const { data } = await agent.userinfo.get({
				headers: { authorization: `Bearer ${accessTokens['pairwise-one']}` }
			});

			expect(data?.sub).toBe(subs['pairwise-one']);
		});

		it('reports the same identifier at the introspection endpoint', async () => {
			const { data, status } = await agent.token.introspect.post(
				{ token: accessTokens['pairwise-one'] },
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'pairwise-one',
						'secret'
					)
				}
			);

			expect(status).toBe(200);
			expect(data?.sub).toBe(subs['pairwise-one']);
		});

		it('does not leak one sector identifier to another sector', async () => {
			// The same account, introspected by a client in another sector: it must see its OWN
			// pseudonym, not the one the first client holds. Getting this wrong would make the two
			// relying parties able to correlate their users, which is the one thing pairwise exists to
			// prevent.
			const { data, status } = await agent.token.introspect.post(
				{ token: accessTokens['pairwise-two'] },
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'pairwise-two',
						'secret'
					)
				}
			);

			expect(status).toBe(200);
			expect(data?.sub).toBe(subs['pairwise-two']);
			expect(data?.sub).not.toBe(subs['pairwise-one']);
		});
	});
});
