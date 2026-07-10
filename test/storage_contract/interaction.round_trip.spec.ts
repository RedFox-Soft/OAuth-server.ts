import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { Interaction } from 'lib/models/interaction.js';
import { Grant } from 'lib/models/grant.js';
import { Session } from 'lib/models/session.js';
import {
	assertStoredMatchesSchema,
	assertNotPersisted,
	storedPayloadFor
} from './round_trip.js';

describe('storage contract: Interaction', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	it('persists every audited field verbatim, derives grantId, and drops the grant instance', async () => {
		const grant = new Grant({ clientId: 'client', accountId: 'account-1' });
		grant.addOIDCScope('openid');
		const grantId = await grant.save();

		const session = new Session({
			uid: 'sess-uid',
			jti: 'sess-1',
			accountId: 'account-1',
			acr: 'acr-1',
			amr: ['pwd']
		});

		const interaction = new Interaction('interaction-1', {
			returnTo: 'https://op.example.com/auth/interaction-1',
			prompt: { name: 'consent', reasons: ['op_scopes_missing'] },
			cookieID: 'cookie-1',
			lastSubmission: { login: { accountId: 'account-1' } },
			accountId: 'account-1',
			params: { client_id: 'client', scope: 'openid', nonce: 'n-1' },
			trusted: ['nonce'],
			session,
			grant,
			cid: 'cid-1',
			deviceCode: 'device-1',
			parJti: 'par-1'
		});
		// result is written later in the flow (post-login)
		interaction.payload.result = {
			login: { accountId: 'account-1', transient: false }
		};

		await interaction.save(3600);

		const stored = assertStoredMatchesSchema(interaction);

		// grantId derived from the Grant instance; the instance itself must NOT be persisted
		expect(stored.grantId).toBe(grantId);
		assertNotPersisted(interaction, ['grant']);

		// freeform sub-objects preserved verbatim
		expect(stored.params).toEqual({
			client_id: 'client',
			scope: 'openid',
			nonce: 'n-1'
		});
		expect(stored.result).toEqual({
			login: { accountId: 'account-1', transient: false }
		});
		expect(stored.prompt).toEqual({
			name: 'consent',
			reasons: ['op_scopes_missing']
		});
		// Session model reduced to its persisted subset
		expect(stored.session).toEqual({
			accountId: 'account-1',
			uid: 'sess-uid',
			cookie: 'sess-1',
			acr: 'acr-1',
			amr: ['pwd']
		});

		// reload exercises Value.Check on the stored shape
		const reloaded = await Interaction.find('interaction-1');
		expect(reloaded).toBeDefined();
		expect(reloaded!.payload.result).toEqual({
			login: { accountId: 'account-1', transient: false }
		});
		expect(reloaded!.payload.deviceCode).toBe('device-1');
	});

	it('persists nothing outside the schema', async () => {
		const interaction = new Interaction('interaction-2', {
			prompt: { name: 'login' },
			params: { client_id: 'client' }
		});
		await interaction.save(3600);

		const stored = storedPayloadFor(interaction)!;
		const schemaKeys = Object.keys(interaction.model.properties);
		for (const key of Object.keys(stored)) {
			expect(schemaKeys).toContain(key);
		}
	});
});
