import getConfig from '../default.config.js';

/*
 * An application of the default bucket, which is the whole point.
 *
 * Rule 2 of bucket resolution — the bucket an application belongs to — pins every bucket but the default
 * one, so the rule under test is the one that reaches a bucket through the *declared resource* the request
 * names. An application of any other bucket would satisfy rule 2 and the spec would pass without that rule
 * existing. The specs bind it to the default bucket, since buckets are not configuration.
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
