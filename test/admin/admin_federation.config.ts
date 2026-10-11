import getConfig from '../default.config.js';

const config = getConfig();

/* Federation is off by default; this suite signs administrators in through a provider. */
export const ApplicationConfig = {
	'federation.enabled': true
};

/* The console's own client: an interaction it starts resolves to the administrators' bucket. */
export const clients = [
	{
		clientId: 'admin-panel',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/admin/callback']
	}
];

export default {
	config
};
