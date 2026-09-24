import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import fc from 'fast-check';

import bootstrap, {
	clearSeededBuckets,
	seedBucket,
	type Setup,
	jsonToFormUrlEncoded
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { getUserStore } from 'lib/adapters/index.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const PASSWORD = 'sup3rsecret';
const SLUG = 'ordering';
const BUCKET_ID = 'ordering-bucket';
const EMAIL = 'bob@ordering.example.com';

/*
 * The two populations, each with the handle a request needs to reach it: an address to send the
 * request to and a client that belongs there.
 */
const AT_DEFAULT = {
	prefix: '',
	clientId: 'default-app',
	redirectUri: 'https://default.example.com/cb'
};
const AT_NAMED = {
	prefix: `/${SLUG}`,
	clientId: 'ordering-app',
	redirectUri: 'https://ordering.example.com/cb'
};

type Where = typeof AT_DEFAULT;

async function authorize(where: Where, cookie: string) {
	const auth = new AuthorizationRequest({
		client_id: where.clientId,
		scope: 'openid',
		redirect_uri: where.redirectUri
	});
	return elysia.handle(
		new Request(
			`http://localhost${where.prefix}/auth?${jsonToFormUrlEncoded(auth.params)}`,
			{ headers: { cookie } }
		)
	);
}

/*
 * Whether the request resolved somebody.
 *
 * A code is the plain case. A consent prompt is the other one, and counting it as "none" would make
 * the property assert something weaker than it claims: consent is asked *of a resolved account*, so a
 * request routed there has already resolved an identity. Only the sign-in prompt means none — it is
 * the server saying it does not know who this is at this address.
 */
function gotAnIdentity(response: Response): boolean {
	const location = response.headers.get('location') ?? '';
	if (location.includes('code=')) return true;
	return location.includes('/ui/') && !location.endsWith('/login');
}

/*
 * A cookie jar, because a string is not one.
 *
 * Appending each `Set-Cookie` to what the last request sent leaves two entries under one name, and the
 * server reads the first — the value that was just replaced. A browser replaces by name, and a model
 * that does not will report the server losing a sign-in it kept.
 */
class Jar {
	private readonly entries = new Map<string, string>();

	accept(headers: readonly string[]): void {
		for (const header of headers) {
			const [pair] = header.split(';');
			const index = pair.indexOf('=');
			if (index > 0)
				this.entries.set(pair.slice(0, index), pair.slice(index + 1));
		}
	}

	get header(): string {
		return [...this.entries]
			.map(([name, value]) => `${name}=${value}`)
			.join('; ');
	}
}

/* Completes a real sign-in at one bucket, into the jar the browser is carrying. */
async function signIn(where: Where, jar: Jar): Promise<void> {
	const prompt = await authorize(where, jar.header);
	jar.accept(prompt.headers.getSetCookie());
	const location = prompt.headers.get('location') ?? '';
	if (!location.includes('/ui/')) return;
	const uid = location.split('/ui/')[1].split('/')[0];

	const loggedIn = await elysia.handle(
		new Request(`http://localhost/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: jar.header
			},
			body: new URLSearchParams({
				username: where === AT_NAMED ? EMAIL : 'ana@default.example.com',
				password: PASSWORD
			})
		})
	);
	jar.accept(loggedIn.headers.getSetCookie());
}

/**
 * @proves For every ordering of sign-ins and requests across two user buckets, a request is answered
 * with an identity only if its own bucket was signed in to.
 */
describe('sign-ins and requests interleaved across buckets', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, {
			config: 'per_bucket_sessions'
		});
		await seedBucket({
			bucketId: BUCKET_ID,
			slug: SLUG,
			clientId: AT_NAMED.clientId,
			accountId: 'bob',
			client: {
				redirectUris: [AT_NAMED.redirectUri],
				'consent.require': false
			}
		});
		await getUserStore(BUCKET_ID).create(
			EMAIL,
			await Bun.password.hash(PASSWORD)
		);
		await getUserStore('redfox').create(
			'ana@default.example.com',
			await Bun.password.hash(PASSWORD)
		);
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * A property rather than a set of cases because the defect class here is an **ordering**, not an
	 * input: one cookie for two populations failed only on the sequences where the second sign-in came
	 * after the first, and an example suite covers the orderings somebody thought of. The generated
	 * sequence is short and the alphabet tiny, so what is being searched is the interleavings.
	 */
	it('answers a request with an identity only where that bucket was signed in to', async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.array(
					fc.constantFrom(
						'signIn:default',
						'signIn:named',
						'request:default',
						'request:named'
					),
					{ minLength: 1, maxLength: 6 }
				),
				async (steps) => {
					const jar = new Jar();
					const signedInto = new Set<string>();

					for (const step of steps) {
						const [action, which] = step.split(':');
						const where = which === 'named' ? AT_NAMED : AT_DEFAULT;

						if (action === 'signIn') {
							await signIn(where, jar);
							signedInto.add(which);
							continue;
						}

						/*
						 * One direction, deliberately: a request may resolve an identity only where its own
						 * bucket was signed in to. Resolving one anywhere else would answer an application
						 * with a subject from a population it has no relationship with, which is the
						 * invariant, and it is the direction an ordering can break silently.
						 *
						 * The converse — that a sign-in survives until it is ended — is a User Case with a
						 * definite answer, and `isolation.spec.ts` asserts it directly. Asserting it here
						 * would mean driving each generated sign-in through consent as well, which tests the
						 * model rather than the partition.
						 */
						const response = await authorize(where, jar.header);
						if (gotAnIdentity(response)) {
							expect({ step, resolved: true }).toEqual({
								step,
								resolved: signedInto.has(which)
							});
						}
					}
				}
			),
			{ numRuns: 25 }
		);
	}, 60000);
});
