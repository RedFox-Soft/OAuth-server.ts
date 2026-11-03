import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { eventBus } from 'lib/event_bus.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	get,
	signedInAccountIds,
	startInteraction
} from '../federation/harness.ts';
import {
	SERVICE_SCOPES,
	keptAccounts,
	linkedProject,
	upstreamPerson,
	type Linked
} from './harness.ts';

function stateOf(url: URL): string {
	return url.searchParams.get('state') ?? '';
}

function scopesOf(url: URL): string[] {
	return (url.searchParams.get('scope') ?? '').split(' ');
}

async function back(query: Record<string, string>) {
	return get(`/federation/callback?${new URLSearchParams(query).toString()}`);
}

/* Leg one, as a browser starts it: the provider's authorization request. */
async function begin(linked: Linked) {
	const { uid, cookie } = await startInteraction('keep-app');
	const start = await get(
		`/ui/${uid}/federation/${linked.provider.id}/start`,
		cookie
	);
	return { uid, cookie, authorizeUrl: new URL(start.location) };
}

/* The provider answers a request with a code, and the browser walks legs two and three. */
async function finish(
	linked: Linked,
	authorizeUrl: URL,
	claims: Record<string, unknown>,
	cookie: string
) {
	await linked.idp.answerToken(
		authorizeUrl,
		claims,
		{},
		{
			access_token: 'kept-access-token',
			refresh_token: 'kept-refresh-token',
			expires_in: 3600
		}
	);
	const callback = await back({
		code: 'upstream-code',
		state: stateOf(authorizeUrl)
	});
	return get(callback.location, cookie);
}

function retries(): { seen: unknown[]; stop: () => void } {
	const seen: unknown[] = [];
	const listen = (event: unknown) => seen.push(event);
	eventBus.on('federation.keep.retried', listen);
	return { seen, stop: () => eventBus.off('federation.keep.retried', listen) };
}

/**
 * @proves A provider that refuses the service's extra scopes does not cost the person their sign-in: the sign-in is
 * sent again once without them and keeps nothing, while a person's own cancel ends the sign-in as before.
 */
describe('a linked sign-in the provider refuses for the service’s scopes', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('is sent again once without them, and the person signs in with nothing kept', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const watch = retries();
		const first = await begin(linked);

		let retried: Awaited<ReturnType<typeof back>>;
		try {
			retried = await back({
				error: 'invalid_scope',
				state: stateOf(first.authorizeUrl)
			});
		} finally {
			watch.stop();
		}
		const again = new URL(retried.location);
		await finish(linked, again, claims, first.cookie);

		expect(again.origin).toBe(linked.idp.origin);
		expect(scopesOf(again)).not.toContain(SERVICE_SCOPES[0]);
		const person = present(
			await getUserStore(DEFAULT_BUCKET_ID).findByEmail(String(claims.email)),
			'the person'
		);
		expect(signedInAccountIds()).toContain(person._id);
		expect(await keptAccounts(person._id)).toEqual([]);
		expect(watch.seen).toEqual([
			expect.objectContaining({ error: 'invalid_scope' })
		]);
	});

	it('is sent again once when the code exchange answers that consent is required', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const first = await begin(linked);
		linked.idp.expectTokenFailure(
			400,
			JSON.stringify({ error: 'invalid_grant', suberror: 'consent_required' })
		);

		const retried = await back({
			code: 'upstream-code',
			state: stateOf(first.authorizeUrl)
		});
		const again = new URL(retried.location);
		await finish(linked, again, claims, first.cookie);

		expect(again.origin).toBe(linked.idp.origin);
		expect(scopesOf(again)).not.toContain(SERVICE_SCOPES[0]);
		const person = await getUserStore(DEFAULT_BUCKET_ID).findByEmail(
			String(claims.email)
		);
		expect(signedInAccountIds()).toContain(present(person, 'the person')._id);
	});

	it('ends as it always did when the person cancelled at the provider', async () => {
		const linked = await linkedProject();
		const first = await begin(linked);

		const answer = await back({
			error: 'access_denied',
			state: stateOf(first.authorizeUrl)
		});

		expect(answer.location.startsWith(`/ui/${first.uid}/login`)).toBe(true);
	});

	it('is not sent a second time when the retry is refused too', async () => {
		const linked = await linkedProject();
		const first = await begin(linked);
		const retried = await back({
			error: 'invalid_scope',
			state: stateOf(first.authorizeUrl)
		});

		const answer = await back({
			error: 'invalid_scope',
			state: stateOf(new URL(retried.location))
		});

		expect(answer.location.startsWith(`/ui/${first.uid}/login`)).toBe(true);
	});

	it('is never retried for a provider that is not linked', async () => {
		const linked = await linkedProject({ linked: false });
		const first = await begin(linked);

		const answer = await back({
			error: 'invalid_scope',
			state: stateOf(first.authorizeUrl)
		});

		expect(answer.location.startsWith(`/ui/${first.uid}/login`)).toBe(true);
	});
});
