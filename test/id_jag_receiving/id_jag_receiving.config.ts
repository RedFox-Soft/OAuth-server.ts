import getConfig from '../default.config.js';

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/*
 * Harness for the receiving side of enterprise-managed authorization (specs/108 story 1): the JWT bearer
 * grant is on, as are DPoP (key-bound ID-JAGs), federation (the trusted provider is a sign-in provider) and
 * client ID metadata documents (an MCP client that is not pre-registered presents one).
 */
export const ApplicationConfig = {
	...getConfig(),
	'jwtBearer.enabled': true,
	'dpop.enabled': true,
	'federation.enabled': true,
	'clientIdMetadataDocument.enabled': true
};

/*
 * `agent` is the MCP client as the project registered it; `agent-without-grant` authenticates but may not use
 * the grant; `spa` holds the grant but cannot authenticate.
 */
export const clients = [
	{
		clientId: 'agent',
		clientSecret: 'agent-secret',
		grantTypes: [JWT_BEARER],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'agent-without-grant',
		clientSecret: 'agent-without-grant-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'spa',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', JWT_BEARER],
		responseTypes: ['code'],
		redirectUris: ['https://spa.example.com/cb']
	}
];

export default {
	config: getConfig()
};
