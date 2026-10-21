import getConfig from '../default.config.js';

const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/*
 * Harness for the issuing side of enterprise-managed authorization (specs/108 story 2): token exchange is
 * on, as is DPoP (a key-bound ID-JAG). Every client signs people in with the code flow, so each holds the ID
 * token and refresh token it later exchanges.
 */
export const ApplicationConfig = {
	...getConfig(),
	'tokenExchange.enabled': true,
	'dpop.enabled': true,
	'revocation.enabled': true,
	scopes: ['openid', 'offline_access']
};

const signsIn = {
	grantTypes: ['authorization_code', 'refresh_token', EXCHANGE],
	responseTypes: ['code']
};

/*
 * `globex-agent` is the agent the connection allows; `other-agent` holds the grant but is not on the
 * connection; `https://agent.globex.example/client.json` is an application whose id is a URL, so the ID-JAG
 * names it as it is; `spa` cannot authenticate; `tickets-sso` is how the outside server itself signs people
 * in through this project, with pairwise identifiers.
 */
export const clients = [
	{
		clientId: 'globex-agent',
		clientSecret: 'globex-agent-secret',
		redirectUris: ['https://agent.globex.example/cb'],
		...signsIn
	},
	{
		clientId: 'other-agent',
		clientSecret: 'other-agent-secret',
		redirectUris: ['https://other.globex.example/cb'],
		...signsIn
	},
	{
		clientId: 'https://agent.globex.example/client.json',
		clientSecret: 'url-agent-secret',
		redirectUris: ['https://agent.globex.example/url-cb'],
		...signsIn
	},
	{
		clientId: 'spa',
		token_endpoint_auth_method: 'none',
		redirectUris: ['https://spa.globex.example/cb'],
		...signsIn
	},
	{
		clientId: 'tickets-sso',
		clientSecret: 'tickets-sso-secret',
		subjectType: 'pairwise',
		redirectUris: ['https://sso.tickets.example/cb'],
		grantTypes: ['authorization_code'],
		responseTypes: ['code']
	}
];

export default {
	config: getConfig()
};
