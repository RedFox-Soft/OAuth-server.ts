import getConfig from '../default.config.js';

const config = getConfig();

/* Federation on, as an instance offering provider buttons has it; one case turns it off and back. */
export const ApplicationConfig = {
	'federation.enabled': true
};

/* One client per bucket the cases compare, so each interaction resolves to the bucket it is about. */
export const clients = Array.from({ length: 8 }, (_, i) => ({
	clientId: `preview-app-${String(i)}`,
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code'],
	responseTypes: ['code'],
	redirectUris: [`http://e.ly/preview-${String(i)}/callback`]
}));

export default {
	config
};
