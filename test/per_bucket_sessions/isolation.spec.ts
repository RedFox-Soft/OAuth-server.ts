import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	agent,
	clearSeededBuckets,
	findSessionSetCookie,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { getUserStore } from 'lib/adapters/index.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const PASSWORD = 'sup3rsecret';
const SLUG = 'acme';

/*
 * The second bucket is given an address, which is what makes any of this observable: a bucket with no
 * slug has no endpoints of its own, so its clients use the bare ones and share the default bucket's
 * cookie exactly as they did before tenancy. Co-existence is a property of addressed buckets.
 */
async function signInToAcme(held: string): Promise<string> {
	const auth = new AuthorizationRequest({
		client_id: 'acme-app',
		scope: 'openid',
		redirect_uri: 'https://acme.example.com/cb'
	});
	const prompt = await elysia.handle(
		new Request(
			`http://localhost/${SLUG}/auth?${new URLSearchParams(
				auth.params as Record<string, string>
			)}`,
			{ headers: { cookie: held } }
		)
	);
	const location = prompt.headers.get('location') ?? '';
	const uid = location.split('/ui/')[1]?.split('/')[0];
	const interactionCookie = (prompt.headers.get('set-cookie') ?? '').split(
		';'
	)[0];

	const loggedIn = await elysia.handle(
		new Request(`http://localhost/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: `${held}; ${interactionCookie}`
			},
			body: new URLSearchParams({
				username: 'bob@acme.example.com',
				password: PASSWORD
			})
		})
	);

	const written = findSessionSetCookie(loggedIn.headers.getSetCookie());
	expect(written).toBeDefined();
	return (written as string).split(';')[0];
}

async function authorizeAtDefault(cookie: string) {
	const auth = new AuthorizationRequest({
		client_id: 'default-app',
		scope: 'openid',
		redirect_uri: 'https://default.example.com/cb'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie }
	});
	return response;
}

/**
 * @proves A browser holding a sign-in in two user buckets is answered as the person of the bucket
 * each request is addressed to, and signing in to one leaves the other's sign-in untouched.
 */
describe('a browser holding a sign-in in two buckets', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme-bucket',
			slug: SLUG,
			clientId: 'acme-app',
			accountId: 'bob',
			/* So a sign-in reaches a code in one step: what is under test is which session answers, not
			 * the consent prompt. */
			client: {
				redirectUris: ['https://acme.example.com/cb'],
				'consent.require': false
			}
		});
		await getUserStore('acme-bucket').create(
			'bob@acme.example.com',
			await Bun.password.hash(PASSWORD)
		);
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * The case the whole partition exists for, and the one that failed before it: the two sign-ins were
	 * one cookie, so the second overwrote the first and an end user was signed out of an application
	 * they had not touched — silently, with nothing to retry.
	 */
	it('leaves the first bucket sign-in intact when a sign-in in the second completes', async () => {
		const held = await setup.login({ accountId: 'ana' });
		expect((await authorizeAtDefault(held)).headers.get('location')).toContain(
			'code='
		);

		const acmeCookie = await signInToAcme(held);

		const again = await authorizeAtDefault(`${held}; ${acmeCookie}`);
		expect(again.headers.get('location')).toContain('code=');
	});

	it('writes the second bucket a cookie of its own', async () => {
		const held = await setup.login({ accountId: 'ana' });

		const acmeCookie = await signInToAcme(held);

		expect(acmeCookie.startsWith(`_session_${SLUG}=`)).toBe(true);
		expect(acmeCookie.startsWith(held.split('=')[0])).toBe(false);
	});

	/*
	 * A security invariant rather than a convenience: the two cookies travel together on every request,
	 * so the partition is only real if a request reads the one its address names. Reading the other
	 * would answer an application with a subject from a population it has no relationship with.
	 */
	it('answers each address with the subject of its own bucket', async () => {
		const held = await setup.login({ accountId: 'ana' });
		const acmeCookie = await signInToAcme(held);
		const both = `${held}; ${acmeCookie}`;

		const atDefault = await authorizeAtDefault(both);
		const atAcme = await elysia.handle(
			new Request(
				`http://localhost/${SLUG}/auth?${new URLSearchParams({
					...(new AuthorizationRequest({
						client_id: 'acme-app',
						scope: 'openid',
						redirect_uri: 'https://acme.example.com/cb'
					}).params as Record<string, string>)
				})}`,
				{ headers: { cookie: both } }
			)
		);

		expect(atDefault.headers.get('location')).toContain('code=');
		expect(atAcme.headers.get('location')).toContain('code=');
		expect(atDefault.headers.get('location')).not.toBe(
			atAcme.headers.get('location')
		);
	});
});
