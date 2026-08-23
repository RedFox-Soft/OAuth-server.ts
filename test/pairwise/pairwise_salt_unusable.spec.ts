import { describe, it, beforeAll, afterAll, expect, spyOn } from 'bun:test';
import url from 'node:url';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { pairwiseSaltStore } from 'lib/adapters/index.js';
import { initPairwiseSalt, pairwiseSalt } from 'lib/configs/pairwiseSalt.js';

/*
 * Failing closed on an unusable salt — spec 023, FR-006 / FR-006a / SC-008.
 *
 * The clarified decision: the server starts, serves everything it can, and refuses only what it
 * cannot answer correctly. It never replaces the stored value, because replacing a salt permanently
 * reassigns every relying party's account key — and the realistic cause of an unusable value (task 35:
 * a driver handing binary back in its own wrapper) recurs on every read, so a replacing server would
 * do that on every single restart while reporting a healthy boot.
 *
 * The state is installed through initPairwiseSalt with a store this suite controls, which is the same
 * seam a restart uses. Restored in afterAll, because the salt is process-wide module state and a spec
 * that left it broken would fail every later pairwise suite in the same run for reasons that look
 * nothing like the cause.
 */

// Holds 16 bytes: present, so there is nothing to provision, and unusable, so there is nothing to
// derive from. Exactly the situation the resolver must refuse rather than repair.
const unusableStore = {
	created: 0,
	replaced: 0,
	async read(): Promise<unknown> {
		return Buffer.alloc(16, 0);
	},
	async create(secret: Buffer): Promise<unknown> {
		this.created += 1;
		return secret;
	},
	async replace(_observed: unknown, secret: Buffer): Promise<unknown> {
		this.replaced += 1;
		return secret;
	}
};

describe('pairwise identifiers: unusable salt', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'pairwise_salt' });
		cookie = await setup.login({
			scope: 'openid email',
			accountId: 'unusable-salt-account'
		});

		const warn = spyOn(console, 'warn').mockImplementation(() => {});
		await initPairwiseSalt(unusableStore);
		warn.mockRestore();
	});

	afterAll(async () => {
		await initPairwiseSalt(pairwiseSaltStore);
	});

	it('holds no salt, and did not write one', () => {
		expect(pairwiseSalt()).toBeNull();
		expect(unusableStore.created).toBe(0);
		expect(unusableStore.replaced).toBe(0);
	});

	it('serves a client that needs no pairwise identifier', async () => {
		// The narrow part of "fail closed narrowly". A deployment whose salt is broken still runs; only
		// the identifiers it cannot reproduce are withheld.
		const auth = new AuthorizationRequest({
			client_id: 'public-one',
			scope: 'openid email'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});

		expect(response.status).toBe(303);
		const location = response.headers.get('location');
		if (!location) throw new Error('no location');
		const { code } = url.parse(location, true).query;

		const { data } = await auth.getToken(code);
		expect(data?.id_token).toBeString();
	});

	// Where the refusal lands is worth being precise about. The authorization endpoint issues a code
	// and needs no subject identifier to do it, so it succeeds — refusing there would mean deriving an
	// identifier nobody asked for just to fail early. The refusal happens at the point of need: the
	// token exchange, which mints the ID token.
	async function codeFor(clientId: string) {
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
		return { auth, code: url.parse(location, true).query.code };
	}

	it('refuses a pairwise client rather than issuing a fresh identifier', async () => {
		const { auth, code } = await codeFor('pairwise-one');

		const { data, error, status } = await auth.getToken(code);

		// What must not happen is a 200 carrying an id_token whose sub nobody can reproduce after the
		// next restart — the relying party would store it as an account key.
		expect(status).not.toBe(200);
		expect(data?.id_token).toBeUndefined();
		expect(error?.value).toHaveProperty('error', 'temporarily_unavailable');
	});

	it('says nothing about the salt or its shape to the client', async () => {
		const { auth, code } = await codeFor('pairwise-one');

		const { data, error } = await auth.getToken(code);

		// An operator learns the reason from the server's own log and from error_detail. A client learns
		// only that the request cannot be served right now — the stored value, its length and its shape
		// are all server state and none of them belong in a response.
		const body = JSON.stringify(data ?? error?.value ?? {});
		for (const leak of ['salt', 'Buffer', 'byte', 'pairwiseSalt']) {
			expect(body).not.toContain(leak);
		}
	});
});
