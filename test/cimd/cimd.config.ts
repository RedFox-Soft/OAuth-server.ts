import getConfig from '../default.config.js';

/*
 * Harness for Client ID Metadata Documents.
 *
 * The capability is off by default because switching it on lets an unauthenticated caller make this
 * server issue an outbound request — a genuine new capability for a deployment to consent to, and the
 * same reason `registration.enabled` defaults off. A spec opts in, exactly as a deployment does.
 *
 * `registration.enabled` is on too, because one of the traps this area has to hold is that a
 * *stored* client whose id happens to be a URL must still resolve from the adapter rather than by
 * retrieval — see research.md D4 on why the branch sits after the adapter read.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientIdMetadataDocument.enabled': true,
	'registration.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default { config: getConfig() };
