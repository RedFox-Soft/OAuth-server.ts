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
import { eventBus } from 'lib/event_bus.js';

const PASSWORD = 'sup3rsecret';
const SLUG = 'acmeout';

async function signInToAcme(held: string): Promise<string> {
	const auth = new AuthorizationRequest({
		client_id: 'acme-logout-app',
		scope: 'openid',
		redirect_uri: 'https://acmeout.example.com/cb'
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
				username: 'bob@acmeout.example.com',
				password: PASSWORD
			})
		})
	);
	const written = findSessionSetCookie(loggedIn.headers.getSetCookie());
	expect(written).toBeDefined();
	return (written as string).split(';')[0];
}

/* Signs out at a bucket's address, following the confirmation the browser is shown. */
async function signOutAt(prefix: string, cookie: string) {
	const page = await elysia.handle(
		new Request(`http://localhost${prefix}/logout`, {
			headers: { cookie, accept: 'text/html' }
		})
	);
	const pageCookie =
		findSessionSetCookie(page.headers.getSetCookie())?.split(';')[0] ?? cookie;
	const html = await page.text();
	const xsrf =
		/name="xsrf"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="xsrf"/.exec(
			html
		);
	const secret = xsrf?.[1] ?? xsrf?.[2];
	expect(secret).toBeTruthy();

	return elysia.handle(
		new Request(`http://localhost${prefix}/logout/confirm`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie: `${cookie}; ${pageCookie}`,
				accept: 'text/html'
			},
			body: new URLSearchParams({ xsrf: secret as string, logout: 'true' })
		})
	);
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
 * @proves A sign-out ends the sign-in of the bucket it is addressed to and no other, and tells no
 * other bucket's applications about it.
 */
describe('signing out at one bucket while signed in to two', () => {
	let setup: Setup;

	beforeAll(async () => {
		/* The area's config is named for its directory, so this borrowed one is named explicitly. */
		setup = await bootstrap(import.meta.url, { config: 'per_bucket' });
		await seedBucket({
			bucketId: 'acme-logout-bucket',
			slug: SLUG,
			clientId: 'acme-logout-app',
			accountId: 'bob',
			client: {
				redirectUris: ['https://acmeout.example.com/cb'],
				'consent.require': false
			}
		});
		await getUserStore('acme-logout-bucket').create(
			'bob@acmeout.example.com',
			await Bun.password.hash(PASSWORD)
		);
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * The end user's case. Before the partition, "sign out" meant every sign-in the browser held — a
	 * demand to abandon one product in order to leave another, and the reason the bare sign-out screen
	 * was reported in the first place.
	 */
	it('leaves the other bucket signed in when a sign-out completes', async () => {
		const held = await setup.login({ accountId: 'ana' });
		const acmeCookie = await signInToAcme(held);

		await signOutAt(`/${SLUG}`, `${held}; ${acmeCookie}`);

		expect((await authorizeAtDefault(held)).headers.get('location')).toContain(
			'code='
		);
	});

	/*
	 * A security invariant, not a nicety: a back-channel logout is a statement to a relying party that
	 * a named subject's session ended. Sent to an application of a population the sign-out did not
	 * concern, it is a false statement about somebody that application has no relationship with, and it
	 * ends a session the end user is still using.
	 */
	it('notifies no other bucket application when a sign-out completes', async () => {
		const held = await setup.login({ accountId: 'ana' });
		const acmeCookie = await signInToAcme(held);

		const notified: string[] = [];
		const listener = (_ctx: unknown, client: { clientId?: string }) =>
			notified.push(client?.clientId ?? 'unknown');
		eventBus.on('backchannel.success', listener);
		try {
			await signOutAt(`/${SLUG}`, `${held}; ${acmeCookie}`);
		} finally {
			eventBus.off('backchannel.success', listener);
		}

		expect(notified).not.toContain('default-app');
	});
});
