import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { TestAdapter } from '../models.js';
import { openConsent, decide } from './flow.ts';

function grantCount(): number {
	return [...TestAdapter.for('Grant').store.keys()].filter((k) =>
		k.startsWith('Grant:')
	).length;
}

/**
 * @proves A decision on the consent page applies only to the account it was shown for: a submission
 * carrying another account, or none, changes nothing and tells the client nothing.
 */
describe('a consent decision and the account it was shown for', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
	});

	async function atConsent() {
		const cookie = await setup.login({ scope: 'openid' });
		return openConsent(
			{ client_id: 'own-app', scope: 'openid email', prompt: 'consent' },
			cookie
		);
	}

	it('grants nothing when the submission names a different account', async () => {
		const page = await atConsent();
		const before = grantCount();

		const response = await decide(page, 'allow', 'somebody-else');

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.headers.get('location')).toBeNull();
		expect(grantCount()).toBe(before);
	});

	it('grants nothing when the submission names no account', async () => {
		const page = await atConsent();
		const before = grantCount();

		const response = await decide(page, 'allow', '');

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.headers.get('location')).toBeNull();
		expect(grantCount()).toBe(before);
	});

	it('delivers no refusal to the client when a decline names a different account', async () => {
		const page = await atConsent();

		const response = await decide(page, 'cancel', 'somebody-else');

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.headers.get('location')).toBeNull();
	});

	it('completes when the submission names the account that was shown', async () => {
		const page = await atConsent();

		const response = await decide(page, 'allow');

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toContain(
			'https://billing.acme.test/cb'
		);
	});
});
