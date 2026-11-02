import getConfig from '../default.config.js';

const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/*
 * Upstream token exchange (specs/118): an agent the person signed in to exchanges their access token for their
 * token at a connected service of the default project. Resource indicators are on so an API (an MCP server) can be
 * asked for, and DPoP so a sender-constrained subject token can be presented.
 */
export const ApplicationConfig = {
	...getConfig(),
	'dpop.enabled': true,
	'resourceIndicators.enabled': true,
	scopes: ['openid']
};

const signsIn = {
	bucketId: 'redfox',
	grantTypes: ['authorization_code', EXCHANGE],
	responseTypes: ['code']
};

/*
 * `agent` is the application the person signs in to and the administrator allows; `other-agent` is another
 * confidential application of the project; `mcp-server` exchanges for an API it is linked to; `spa` cannot
 * authenticate; `no-grant` lacks the token exchange grant; `elsewhere-app` belongs to another project;
 * `self-registered` registered itself.
 */
export const clients = [
	{
		clientId: 'agent',
		clientSecret: 'agent-secret',
		redirectUris: ['https://agent.example/cb'],
		...signsIn
	},
	{
		clientId: 'other-agent',
		clientSecret: 'other-agent-secret',
		redirectUris: ['https://other.example/cb'],
		...signsIn
	},
	{
		clientId: 'mcp-server',
		clientSecret: 'mcp-server-secret',
		redirectUris: ['https://mcp.example/cb'],
		...signsIn
	},
	{
		clientId: 'spa',
		token_endpoint_auth_method: 'none',
		redirectUris: ['https://spa.example/cb'],
		...signsIn
	},
	{
		clientId: 'no-grant',
		clientSecret: 'no-grant-secret',
		redirectUris: ['https://no-grant.example/cb'],
		...signsIn,
		grantTypes: ['authorization_code']
	},
	{
		clientId: 'elsewhere-app',
		clientSecret: 'elsewhere-app-secret',
		redirectUris: ['https://elsewhere.example/cb'],
		...signsIn,
		bucketId: 'elsewhere'
	},
	{
		clientId: 'self-registered',
		clientSecret: 'self-registered-secret',
		registeredDynamically: true,
		redirectUris: ['https://self.example/cb'],
		...signsIn
	}
];

export default {
	config: getConfig()
};
