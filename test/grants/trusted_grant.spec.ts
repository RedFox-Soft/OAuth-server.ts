import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { seedClient } from '../test_helper.js';
import { loadExistingGrant } from 'lib/addon/account.ts';
import {
	DEFAULT_REQUEST_BUCKET,
	OIDCContext
} from 'lib/helpers/oidc_context.ts';
import { Session } from 'lib/models/session.ts';
import { Client } from 'lib/models/client.ts';
import { present } from 'test/shape.js';

/* A request that has resolved a client, a fresh session and an account, and nothing else. */
async function requestFor(clientId: string, accountId: string) {
	const oidc = new OIDCContext({ params: {}, bucket: DEFAULT_REQUEST_BUCKET });
	oidc.entity(
		'Client',
		present(await Client.tryFind(clientId), `client ${clientId}`)
	);
	oidc.entity('Session', new Session());
	// loadExistingGrant reads only the id; the claims are the shape an account resolves to.
	oidc.entity('Account', {
		accountId,
		bucketId: DEFAULT_REQUEST_BUCKET._id,
		provisioned: false,
		claims: async () => ({
			sub: accountId,
			email: `${accountId}@example.com`,
			email_verified: true
		})
	});
	return oidc;
}

/**
 * @proves Consent is skipped only for a client an operator marked trusted, and then only for the
 * scope actually requested.
 */
describe('loadExistingGrant for consent-not-required clients', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		for (const [clientId, requireConsent] of [
			['first-party', false],
			['needs-consent', true]
		] as const) {
			seedClient({
				clientId,
				clientSecret: 'secret',
				'consent.require': requireConsent,
				redirectUris: [`https://${clientId}.example.com/cb`]
			});
		}
	});

	it('auto-creates a trusted grant that grants the full requested scope', async () => {
		// Regression: the auto-created grant must be `trusted`. A non-trusted grant
		// has no scopes, so getOIDCScopeFiltered() returns nothing and interactions()
		// denies the request with access_denied ("no scope was granted").
		const oidc = await requestFor('first-party', 'acc-1');

		const grant = await loadExistingGrant(oidc);

		expect(grant).toBeTruthy();
		const trusted = present(grant, 'an auto-created grant');
		expect(trusted.payload.trusted).toBe(true);
		expect(trusted.payload.accountId).toBe('acc-1');
		expect(trusted.payload.clientId).toBe('first-party');
		// A trusted grant returns whatever scope is requested.
		expect(trusted.getOIDCScopeFiltered(['openid'])).toBe('openid');
	});

	it('returns nothing for a client that requires consent and has no existing grant', async () => {
		const oidc = await requestFor('needs-consent', 'acc-2');

		expect(await loadExistingGrant(oidc)).toBeUndefined();
	});
});
