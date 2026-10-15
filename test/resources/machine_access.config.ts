import getConfig from '../default.config.js';

/*
 * Harness for machine tokens to a declared resource.
 *
 * Client ID Metadata Documents are on because one of the clients a machine token must not reach a
 * declared resource for is the one with no stored record at all — a client known only by the document it
 * hosts — and a deployment has to switch that capability on before such a client can exist.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true,
	'clientIdMetadataDocument.enabled': true
};

/*
 * `client` is an administrator-created application of the bucket that declares the resource; `outsider`
 * is one of another bucket; `self-registered` belongs to the declaring bucket but registered itself.
 * Each is bound to its bucket by the spec, since buckets are not configuration.
 */
export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'outsider',
		clientSecret: 'outsider-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	},
	{
		clientId: 'self-registered',
		clientSecret: 'self-registered-secret',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: []
	}
];

export default { config: getConfig() };
