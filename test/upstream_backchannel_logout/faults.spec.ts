import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import { errorStore } from 'lib/adapters/index.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { eventBus } from 'lib/event_bus.ts';
import { Session } from 'lib/models/session.js';
import bootstrap from '../test_helper.js';
import {
	assertNoPendingInterceptors,
	mock as mockHttp
} from '../fetch_mock.js';
import {
	CLIENT_AT_IDP,
	keysServedForLogout,
	logoutEndpointOf,
	relyingPartyListening,
	sendLogout,
	signInThroughProvider,
	upstreamOfDefaultBucket
} from './helpers.ts';

const ROUTE = '/federation/backchannel-logout';

/* Everything emitted under `name` while `run` runs. */
async function heard(
	name: string,
	run: () => Promise<unknown>
): Promise<unknown[]> {
	const events: unknown[] = [];
	const listener = (payload: unknown) => events.push(payload);
	eventBus.on(name, listener);
	try {
		await run();
	} finally {
		eventBus.off(name, listener);
	}
	return events;
}

/**
 * @proves An operator learns of every logout an upstream provider sends — accepted with how many sessions it
 * ended, or refused with why — without the person's upstream identifiers, and a fault while ending sessions
 * is answered as Back-Channel Logout 1.0 requires yet still recorded as a fault (spec 073 FR-015, FR-017).
 */
describe('what an operator sees of upstream logouts', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		resetQueue();
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('records a fault while ending a session, answering the provider that the logout failed', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		await signInThroughProvider(upstream, {
			sub: 'kc-fault-1',
			sid: 'kc-fault-session-1'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening('https://client.example.com');
		spyOn(Session.prototype, 'destroy').mockRejectedValue(
			new Error('the datastore is unavailable')
		);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-fault-1',
				sid: 'kc-fault-session-1'
			})
		);
		await flushForTest();

		expect(res.status).toBe(400);
		expect(res.json).toEqual({ error: 'logout_failed' });
		const page = await errorStore.list({ route: ROUTE });
		expect(page.groups[0]).toMatchObject({ status: 500, surface: 'oauth' });
	});

	it('answers that the provider’s keys could not be read, recording no fault', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		await signInThroughProvider(upstream, {
			sub: 'kc-fault-2',
			sid: 'kc-fault-session-2'
		});
		mockHttp(upstream.stub.origin).intercept({ path: '/jwks' }).reply(503);
		await flushForTest();
		const before = (await errorStore.list({ route: ROUTE })).total;

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-fault-2',
				sid: 'kc-fault-session-2'
			})
		);
		await flushForTest();

		expect(res.json).toEqual({ error: 'temporarily_unavailable' });
		expect((await errorStore.list({ route: ROUTE })).total).toBe(before);
	});

	it('reports an accepted logout with the provider and the number of sessions it ended', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		await signInThroughProvider(upstream, {
			sub: 'kc-report-1',
			sid: 'kc-report-session-1'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening('https://client.example.com');
		const token = await upstream.stub.logoutToken({
			aud: CLIENT_AT_IDP,
			sub: 'kc-report-1',
			sid: 'kc-report-session-1'
		});

		const events = await heard('upstream.logout.success', () =>
			sendLogout(logoutEndpointOf(upstream.bucket), token)
		);

		expect(events).toEqual([
			{
				bucketId: upstream.bucket._id,
				providerId: upstream.provider.id,
				ended: 1
			}
		]);
	});

	it('reports a refusal of an authenticated provider with the provider and the reason', async () => {
		const upstream = await upstreamOfDefaultBucket('kc', {
			acceptsBackChannelLogout: false
		});
		await signInThroughProvider(upstream, {
			sub: 'kc-report-2',
			sid: 'kc-report-session-2'
		});
		await keysServedForLogout(upstream.stub);
		const token = await upstream.stub.logoutToken({
			aud: CLIENT_AT_IDP,
			sub: 'kc-report-2',
			sid: 'kc-report-session-2'
		});

		const events = await heard('upstream.logout.refused', () =>
			sendLogout(logoutEndpointOf(upstream.bucket), token)
		);

		expect(events).toEqual([
			{
				bucketId: upstream.bucket._id,
				providerId: upstream.provider.id,
				reason: 'not_permitted'
			}
		]);
	});

	it('reports neither the person’s upstream subject nor their upstream session', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		await signInThroughProvider(upstream, {
			sub: 'kc-private-subject',
			sid: 'kc-private-session'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening('https://client.example.com');
		const accepted = await upstream.stub.logoutToken({
			aud: CLIENT_AT_IDP,
			sub: 'kc-private-subject',
			sid: 'kc-private-session'
		});
		const refused = await upstream.stub.logoutToken({
			aud: CLIENT_AT_IDP,
			sub: 'kc-private-subject',
			sid: 'kc-private-session',
			nonce: 'n'
		});

		const events = [
			...(await heard('upstream.logout.success', () =>
				sendLogout(logoutEndpointOf(upstream.bucket), accepted)
			)),
			...(await heard('upstream.logout.refused', () =>
				sendLogout(logoutEndpointOf(upstream.bucket), refused)
			))
		];

		expect(events).toHaveLength(2);
		const reported = JSON.stringify(events);
		expect(reported).not.toContain('kc-private-subject');
		expect(reported).not.toContain('kc-private-session');
	});
});
