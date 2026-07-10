import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ReplayDetection } from 'lib/models/replay_detection.js';
import { assertStoredMatchesSchema, storedPayloadFor } from './round_trip.js';

describe('storage contract: ReplayDetection', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	it('persists exactly its schema-declared fields (incl. iss) and round-trips', async () => {
		const iss = 'https://op.example.com';
		const jti = 'replay-detection-round-trip';

		const inst = new ReplayDetection({ jti, iss });
		await inst.save(3600);

		// no-leak + no-loss against the schema (source of truth)
		const stored = assertStoredMatchesSchema(inst);

		// iss is the field this flip must not drop
		expect(stored.iss).toBe(iss);
		expect(stored.jti).toBe(jti);

		// reload exercises Value.Check on the stored shape
		const reloaded = await ReplayDetection.find(jti);
		expect(reloaded).toBeDefined();
		expect(reloaded!.payload.iss).toBe(iss);
	});

	it('does not persist an undeclared field', async () => {
		const jti = 'replay-detection-no-leak';
		const inst = new ReplayDetection({ jti, iss: 'https://op.example.com' });
		await inst.save(3600);

		const stored = storedPayloadFor(inst)!;
		// every persisted key must be a schema property
		const schemaKeys = Object.keys(inst.model.properties);
		for (const key of Object.keys(stored)) {
			expect(schemaKeys).toContain(key);
		}
	});
});
