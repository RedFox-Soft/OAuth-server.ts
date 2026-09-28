import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { adapter, checkedAdapter } from 'lib/adapters/index.ts';
import { TotpAttemptPayload } from 'lib/totp/types.js';

const TTL = 60;

/**
 * @proves An area read directly, not through a model class, never hands back a record its own schema
 * refuses: what a writer stored comes back as written, and a record that no longer has the shape the
 * reader relies on — tampered, or left by an older writer — is not found, as a model treats one.
 */
describe('checked reads of a directly read area', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	const attempts = () => checkedAdapter('TotpAttempt', TotpAttemptPayload);
	const attempt = () => ({
		accountId: 'account-1',
		failures: 2,
		windowStart: epochTime(),
		exp: epochTime() + TTL
	});

	it('returns a record its schema accepts as it was written', async () => {
		const written = attempt();
		await attempts().upsert('checked-accepts', written, TTL);

		expect(await attempts().find('checked-accepts')).toEqual(written);
	});

	it('does not return a record its schema refuses', async () => {
		// Written past the reader, the way a record the reader did not write reaches the store.
		await adapter('TotpAttempt').upsert(
			'checked-refuses',
			{ ...attempt(), failures: 'many' },
			TTL
		);

		expect(await attempts().find('checked-refuses')).toBeUndefined();
	});
});
