import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	jsonToFormUrlEncoded,
	agent,
	clearSeededBuckets,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { getUserStore } from 'lib/adapters/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const SLUG = 'acme';

/**
 * @proves An authorization request addressed to a named user bucket is answered by that bucket — it
 * identifies itself as the issuer the bucket's own metadata declares, and an address naming no bucket
 * is answered as no address at all.
 */
describe('a request addressed to a named bucket', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme-bucket',
			slug: SLUG,
			clientId: 'acme-app',
			accountId: 'bob'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * Parsed and compared exactly rather than matched as a substring: the instance issuer is a prefix of
	 * every bucket's, so a containment check would pass on the wrong one in the direction that matters.
	 */
	function issuerOf(response: Response): string | null {
		const location = response.headers.get('location') ?? '';
		return new URL(location).searchParams.get('iss');
	}

	/*
	 * A refusal reaches the caller one of two ways — delivered to the client through the response mode,
	 * or answered directly when the request never earned a redirect. Both are normative protocol
	 * surface, so the error code is read from whichever carried it rather than from one of them.
	 */
	async function refusalOf(response: Response): Promise<string | null> {
		const location = response.headers.get('location');
		if (location) return new URL(location).searchParams.get('error');
		return ((await response.json()) as { error?: string }).error ?? null;
	}

	async function authorizeAt(
		prefix: string,
		clientId: string,
		cookie: string,
		redirectUri = 'https://acme.example.com/cb'
	) {
		const auth = new AuthorizationRequest({
			client_id: clientId,
			scope: 'openid',
			redirect_uri: redirectUri
		});
		const query = jsonToFormUrlEncoded(auth.params);
		return elysia.handle(
			new Request(`http://localhost${prefix}/auth?${query}`, {
				headers: { cookie }
			})
		);
	}

	/*
	 * RFC 9207 puts the issuer in the authorization response so a client can tell which server answered
	 * it — the defence against a mix-up between two servers a client talks to. Two buckets are two
	 * issuers, so the same defence has to distinguish them, and it only does if this value follows the
	 * address rather than the instance.
	 */
	it('identifies itself by the bucket issuer rather than the instance issuer', async () => {
		const cookie = await setup.login({
			accountId: 'bob',
			bucketId: 'acme-bucket'
		});

		const response = await authorizeAt(`/${SLUG}`, 'acme-app', cookie);

		expect(issuerOf(response)).toBe(`${ISSUER}/${SLUG}`);
	});

	it('identifies itself by the instance issuer at the bare address', async () => {
		const cookie = await setup.login({ accountId: 'ana' });

		const response = await authorizeAt(
			'',
			'default-app',
			cookie,
			'https://default.example.com/cb'
		);

		expect(issuerOf(response)).toBe(ISSUER);
	});

	/*
	 * Answered as an address that does not exist, rather than quietly served as the default bucket's:
	 * falling back would answer one population's endpoint at another population's address, and would
	 * make a mistyped tenant look like it worked.
	 */
	it('answers nothing at an address naming no bucket', async () => {
		const response = await authorizeAt(
			'/nosuchbucket',
			'default-app',
			'',
			'https://default.example.com/cb'
		);

		expect(response.status).toBe(404);
	});

	/*
	 * The address selects among an operator's choices and must never create one. Without this, the
	 * prefix would become a way to move a client into a population its operator never put it in — and
	 * the tokens it received would carry that population's issuer, which is the whole point of having
	 * one.
	 */
	it('refuses a client of one bucket at another bucket address', async () => {
		const cookie = await setup.login({ accountId: 'ana' });

		const response = await authorizeAt(
			`/${SLUG}`,
			'default-app',
			cookie,
			'https://default.example.com/cb'
		);

		/* The refusal is delivered through the response mode and carries the addressed bucket's `iss`
		 * like any other response from that address — what is being proved is the error, not its
		 * absence. */
		expect(await refusalOf(response)).toBe('unauthorized_client');
	});

	it('refuses a client of a named bucket at the bare address', async () => {
		const cookie = await setup.login({
			accountId: 'bob',
			bucketId: 'acme-bucket'
		});

		const response = await authorizeAt(
			'',
			'acme-app',
			cookie,
			'https://acme.example.com/cb'
		);

		expect(await refusalOf(response)).toBe('unauthorized_client');
	});

	/*
	 * The issuer a *resumed* request carries.
	 *
	 * A sign-in that goes through the interaction screens produces its authorization response from a
	 * different place than one satisfied by an existing session — the resume path builds its own
	 * context, and nothing about the original address survives into it except the stored interaction.
	 * So this is a second route to the same claim, and it is the one that was wrong: the address was
	 * remembered by the request and forgotten by the resumption.
	 */
	it('identifies itself by the bucket issuer after a sign-in through the interaction', async () => {
		const password = 'sup3rsecret';
		await getUserStore('acme-bucket').create(
			'carol@acme.example.com',
			await Bun.password.hash(password)
		);

		const prompt = await authorizeAt(`/${SLUG}`, 'acme-app', '');
		const location = prompt.headers.get('location') ?? '';
		expect(location).toContain('/ui/');
		const [, , uid] = location.split('/');
		const interactionCookie = prompt.headers.get('set-cookie') ?? '';

		const { response } = await agent
			.ui({ uid: uid })
			.login.post(
				{ username: 'carol@acme.example.com', password },
				{ headers: { cookie: interactionCookie } }
			);

		expect(issuerOf(response)).toBe(`${ISSUER}/${SLUG}`);
	});

	/*
	 * An authorization failure is delivered to the client's redirect_uri, at a bucket's address exactly
	 * as at the bare one.
	 *
	 * RFC 6749 §4.1.2.1 makes that delivery normative, and it is easy to lose here without noticing:
	 * the error handler decides by comparing the matched route against a fixed name, and every protocol
	 * endpoint is mounted twice. A prefixed route matched neither comparison, so a named bucket
	 * answered a protocol error as a bare 400 the client never saw as one — and emitted it as
	 * `server_error` rather than `authorization.error`, so a deployment watching for failures saw none.
	 */
	it('delivers an authorization failure to the client rather than answering it directly', async () => {
		const refused = await elysia.handle(
			new Request(
				`http://localhost/${SLUG}/auth?client_id=acme-app&scope=openid&response_type=code&redirect_uri=${encodeURIComponent('https://acme.example.com/cb')}`
			)
		);

		expect(refused.status).toBe(303);
		const location = new URL(refused.headers.get('location') ?? '');
		expect(location.origin + location.pathname).toBe(
			'https://acme.example.com/cb'
		);
		expect(location.searchParams.get('error')).toBe('invalid_request');
		expect(location.searchParams.get('iss')).toBe(`${ISSUER}/${SLUG}`);
	});
});
