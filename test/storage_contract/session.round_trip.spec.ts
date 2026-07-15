import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { Session } from 'lib/models/session.js';
import {
	assertStoredMatchesSchema,
	assertNotPersisted,
	storedPayloadFor
} from './round_trip.js';

describe('storage contract: Session', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('persists the full session (state + authorizations verbatim) and round-trips', async () => {
		const session = new Session({
			uid: 'session-uid-1',
			jti: 'session-1',
			accountId: 'account-1',
			loginTs: epochTime(),
			amr: ['pwd', 'otp'],
			acr: 'urn:mace:incommon:iap:silver',
			transient: true,
			// `state` is an open object (additionalProperties: true) — extra keys must survive verbatim
			state: {
				secret: 'csrf-secret',
				clientId: 'client',
				state: 'opaque-state',
				postLogoutRedirectUri: 'https://client.example.com/post-logout',
				extra: 'must-be-kept'
			},
			authorizations: {
				client: { sid: 'sid-1', grantId: 'grant-1' }
			}
		});
		// instance-only field — must never reach storage
		session.touched = true;

		await session.save();

		const stored = assertStoredMatchesSchema(session);

		expect(stored.state).toEqual(session.payload.state);
		expect(stored.authorizations).toEqual(session.payload.authorizations);
		assertNotPersisted(session, ['touched']);

		const reloaded = await Session.find('session-1');
		expect(reloaded).toBeDefined();
		expect((reloaded!.payload.state as { extra?: string }).extra).toBe(
			'must-be-kept'
		);
		expect(reloaded!.payload.authorizations?.client?.grantId).toBe('grant-1');
	});

	it('persists nothing outside the schema', async () => {
		const session = new Session({ uid: 'session-uid-2', jti: 'session-2' });
		session.loginAccount({ accountId: 'account-2', amr: ['pwd'] });
		await session.save();

		const stored = storedPayloadFor(session)!;
		const schemaKeys = Object.keys(session.model.properties);
		for (const key of Object.keys(stored)) {
			expect(schemaKeys).toContain(key);
		}
	});
});
