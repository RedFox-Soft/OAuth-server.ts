import getConfig from '../default.config.js';
import {
	ApplicationConfig as exchangeSettings,
	clients as exchangeClients
} from '../upstream_tokens/upstream_tokens.config.ts';

/*
 * Tokens kept from a sign-in (specs/120): a person signs in to the default project through a sign-in provider linked
 * to one of its connected services, and an agent then exchanges for the kept account as in specs/118. Federation is
 * on, and the exchange suite's settings and applications are reused so the exchange runs as it does there.
 */
export const ApplicationConfig = {
	...exchangeSettings,
	'federation.enabled': true
};

export const clients = [
	...exchangeClients,
	{
		clientId: 'keep-app',
		token_endpoint_auth_method: 'none',
		bucketId: 'redfox',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/keep/callback']
	}
];

export default {
	config: getConfig()
};
