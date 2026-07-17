import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap from '../test_helper.js';
import { loadExistingGrant } from 'lib/addon/account.ts';

describe('loadExistingGrant for consent-not-required clients', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('auto-creates a trusted grant that grants the full requested scope', async () => {
		// Regression: the auto-created grant must be `trusted`. A non-trusted grant
		// has no scopes, so getOIDCScopeFiltered() returns nothing and interactions()
		// denies the request with access_denied ("no scope was granted").
		const oidc = {
			client: { clientId: 'first-party', 'consent.require': false },
			result: undefined,
			session: { grantIdFor: () => undefined },
			account: { accountId: 'acc-1' }
		};

		const grant = await loadExistingGrant(oidc);

		expect(grant).toBeTruthy();
		expect(grant!.payload.trusted).toBe(true);
		expect(grant!.payload.accountId).toBe('acc-1');
		expect(grant!.payload.clientId).toBe('first-party');
		// A trusted grant returns whatever scope is requested.
		expect(grant!.getOIDCScopeFiltered(['openid'])).toBe('openid');
	});

	it('returns nothing for a client that requires consent and has no existing grant', async () => {
		const oidc = {
			client: { clientId: 'needs-consent', 'consent.require': true },
			result: undefined,
			session: { grantIdFor: () => undefined },
			account: { accountId: 'acc-2' }
		};

		expect(await loadExistingGrant(oidc)).toBeUndefined();
	});
});
