import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { Grant } from 'lib/models/grant.js';
import { assertStoredMatchesSchema, storedPayloadFor } from './round_trip.js';

describe('storage contract: Grant', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	it('persists the full aggregate (incl. accountId) and freeform sub-objects verbatim', async () => {
		const grant = new Grant({ clientId: 'client', accountId: 'account-xyz' });
		grant.addOIDCScope('openid profile email');
		grant.addOIDCClaims(['email', 'given_name']);
		grant.addResourceScope('https://rs.example.com', 'read write');
		grant.rejectOIDCScope('phone');
		grant.rejectOIDCClaims(['address']);
		grant.addRar({
			type: 'account_information',
			locations: ['https://rs.example.com']
		});

		const grantId = await grant.save();

		const stored = assertStoredMatchesSchema(grant);

		// accountId is the field a naive projection would drop
		expect(stored.accountId).toBe('account-xyz');
		expect(stored.clientId).toBe('client');

		// freeform / nested aggregate structures must survive verbatim (shallow projection)
		expect(stored.openid).toEqual(grant.payload.openid);
		expect(stored.resources).toEqual(grant.payload.resources);
		expect(stored.rejected).toEqual(grant.payload.rejected);
		expect(stored.rar).toEqual(grant.payload.rar);

		// reload exercises Value.Check on the stored shape
		const reloaded = await Grant.find(grantId);
		expect(reloaded).toBeDefined();
		expect(reloaded!.payload.accountId).toBe('account-xyz');
		expect(reloaded!.getOIDCScopeEncountered()).toContain('email');
	});

	it('persists nothing outside the schema', async () => {
		const grant = new Grant({ clientId: 'client', accountId: 'account-2' });
		await grant.save();

		const stored = storedPayloadFor(grant)!;
		const schemaKeys = Object.keys(grant.model.properties);
		for (const key of Object.keys(stored)) {
			expect(schemaKeys).toContain(key);
		}
	});
});
