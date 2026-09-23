import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap from '../test_helper.js';
import { loadExistingGrant } from 'lib/addon/account.ts';
import {
	DEFAULT_REQUEST_BUCKET,
	OIDCContext,
	type Account
} from 'lib/helpers/oidc_context.ts';
import { Session } from 'lib/models/session.ts';
import type { Client } from 'lib/models/client/types.ts';

/* A request that has resolved a client, a fresh session and an account, and nothing else. */
function requestFor(client: Record<string, unknown>, accountId: string) {
	const oidc = new OIDCContext({ params: {}, bucket: DEFAULT_REQUEST_BUCKET });
	// Only the members loadExistingGrant reads; a full client and account add nothing here.
	oidc.entity('Client', client as unknown as Client);
	oidc.entity('Session', new Session());
	oidc.entity('Account', { accountId } as unknown as Account);
	return oidc;
}

/**
 * @proves Consent is skipped only for a client an operator marked trusted, and then only for the
 * scope actually requested.
 */
describe('loadExistingGrant for consent-not-required clients', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('auto-creates a trusted grant that grants the full requested scope', async () => {
		// Regression: the auto-created grant must be `trusted`. A non-trusted grant
		// has no scopes, so getOIDCScopeFiltered() returns nothing and interactions()
		// denies the request with access_denied ("no scope was granted").
		const oidc = requestFor(
			{ clientId: 'first-party', 'consent.require': false },
			'acc-1'
		);

		const grant = await loadExistingGrant(oidc);

		expect(grant).toBeTruthy();
		expect(grant!.payload.trusted).toBe(true);
		expect(grant!.payload.accountId).toBe('acc-1');
		expect(grant!.payload.clientId).toBe('first-party');
		// A trusted grant returns whatever scope is requested.
		expect(grant!.getOIDCScopeFiltered(['openid'])).toBe('openid');
	});

	it('returns nothing for a client that requires consent and has no existing grant', async () => {
		const oidc = requestFor(
			{ clientId: 'needs-consent', 'consent.require': true },
			'acc-2'
		);

		expect(await loadExistingGrant(oidc)).toBeUndefined();
	});
});
