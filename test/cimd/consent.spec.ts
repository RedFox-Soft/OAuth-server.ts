import { describe, it, expect } from 'bun:test';

import {
	buildConsentView,
	documentIdentityFor
} from 'lib/interactions/consentView.ts';

/*
 * What the End-User is shown about a client that identified itself with a document it hosts.
 *
 * The name on the screen is whatever that document claims, so on its own it proves nothing — which is
 * why the draft's §6.4 and the MCP security considerations both require the hostnames beside it: the
 * domain is the part that was actually proved. The loopback warning is a stated SHOULD, because such a
 * document cannot establish which local process will receive the authorization code.
 */

const IDENTIFIER = 'https://app.example.com/oauth/client-metadata.json';

describe('identity facts for a document-identified client', () => {
	it('names the identifier host and the redirect host', () => {
		const identity = documentIdentityFor({
			clientId: IDENTIFIER,
			redirectUri: 'https://app.example.com/callback',
			redirectUris: ['https://app.example.com/callback']
		});

		expect(identity.clientIdHostname).toBe('app.example.com');
		expect(identity.redirectHostname).toBe('app.example.com');
		expect(identity.loopbackOnly).toBeUndefined();
	});

	it('notices that the redirect leaves the identifier host', () => {
		const identity = documentIdentityFor({
			clientId: IDENTIFIER,
			redirectUri: 'https://cdn.elsewhere.example/cb',
			redirectUris: ['https://cdn.elsewhere.example/cb']
		});

		expect(identity.clientIdHostname).toBe('app.example.com');
		expect(identity.redirectHostname).toBe('cdn.elsewhere.example');
	});

	it('warns when every offered redirect target is loopback', () => {
		for (const uris of [
			['http://127.0.0.1:33418/callback'],
			['http://localhost:7777/cb', 'http://127.0.0.1:7777/cb']
		]) {
			const identity = documentIdentityFor({
				clientId: IDENTIFIER,
				redirectUri: uris[0],
				redirectUris: uris
			});
			expect(identity.loopbackOnly).toBe(true);
		}
	});

	/*
	 * A document offering a real HTTPS target as well is not in the same position: the domain it proved
	 * is somewhere the code can actually be sent, so the warning would be noise.
	 */
	it('does not warn when a non-loopback target is also offered', () => {
		const identity = documentIdentityFor({
			clientId: IDENTIFIER,
			redirectUri: 'http://127.0.0.1:1/cb',
			redirectUris: ['http://127.0.0.1:1/cb', 'https://app.example.com/cb']
		});

		expect(identity.loopbackOnly).toBeUndefined();
	});

	/*
	 * An ordinary registered client gets none of this. An operator vouched for it, so there is no
	 * domain for the End-User to weigh and a hostname line would be noise on every consent screen the
	 * server has ever shown.
	 */
	it('says nothing about an ordinary registered client', () => {
		for (const clientId of ['admin-panel', 'client', undefined]) {
			expect(
				documentIdentityFor({
					clientId,
					redirectUri: 'https://app.example.com/cb',
					redirectUris: ['https://app.example.com/cb']
				})
			).toEqual({});
		}
	});
});

describe('the consent view carries the identity facts through', () => {
	it('merges them onto the view the page renders', () => {
		const view = buildConsentView({
			uid: 'u1',
			clientName: 'Example MCP Client',
			details: { missingOIDCScope: ['openid'] },
			identity: documentIdentityFor({
				clientId: IDENTIFIER,
				redirectUri: 'http://127.0.0.1:33418/callback',
				redirectUris: ['http://127.0.0.1:33418/callback']
			})
		});

		expect(view.clientIdHostname).toBe('app.example.com');
		expect(view.loopbackOnly).toBe(true);
		expect(view.permissions).toHaveLength(1);
	});

	it('leaves the view unchanged when there are no identity facts', () => {
		const view = buildConsentView({
			uid: 'u1',
			clientName: 'Registered App',
			details: {}
		});

		expect(view.clientIdHostname).toBeUndefined();
		expect(view.redirectHostname).toBeUndefined();
		expect(view.loopbackOnly).toBeUndefined();
	});
});
