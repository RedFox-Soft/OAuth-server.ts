import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Every capability the suite probes is on. A disabled endpoint 404s at the feature gate before the
 * CORS layer runs at all (lib/plugins/featureGate.ts), so a spec that forgot to enable one would
 * assert the absence of a header for entirely the wrong reason. The flag-off cases turn a single
 * capability back off per test, deliberately.
 *
 * `cors.enabled` is left at its default so the suite exercises the shipped default; the kill-switch
 * cases flip it per test.
 */
export const ApplicationConfig = {
	'par.enabled': true,
	'revocation.enabled': true,
	'deviceFlow.enabled': true,
	'userinfo.enabled': true,
	'clientCredentials.enabled': true,
	'dpop.enabled': true,
	'dpop.nonceSecret': Buffer.alloc(32, 0),
	/*
	 * On so that a client id naming a document is one this deployment would resolve by fetching it —
	 * the case where a CORS lookup that resolved clients the way the endpoints do would fetch too.
	 */
	'clientIdMetadataDocument.enabled': true
};

export const clients = [
	/*
	 * The browser app: each case lists its origins on it. Confidential rather than
	 * public only so `client_credentials` gives the suite a 200 from /token without standing up a
	 * full authorization-code flow — the CORS layer never looks at the grant type.
	 */
	{
		clientId: 'cors-client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'client_credentials'],
		redirectUris: ['https://app.example.com/cb']
	},
	// Lists no origins, so no origin can ever be allowed for it.
	{
		clientId: 'cors-orphan',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'client_credentials'],
		redirectUris: ['https://orphan.example.com/cb']
	}
];

export default {
	config
};
