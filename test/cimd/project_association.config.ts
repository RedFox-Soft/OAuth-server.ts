import getConfig from '../default.config.js';

/*
 * A client belonging to no project, which is the whole point.
 *
 * Rule 2 of bucket resolution — a client assigned to a project — must miss, so that the rule under
 * test is the one that reaches a project through the *declared resource* the request names. A client
 * seeded into a project would satisfy rule 2 and the spec would pass without the new rule existing.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientIdMetadataDocument.enabled': true,
	'registration.enabled': true
};

export const clients = [
	{
		clientId: 'unaffiliated',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://app.example.com/callback']
	}
];

export default { config: getConfig() };
