import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'federation.enabled': true
};

/* One client per project shape, each bound to its own bucket by the spec. */
const client = (clientId: string) => ({
	clientId,
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code'],
	responseTypes: ['code'],
	redirectUris: ['http://e.ly/layout/callback']
});

export const clients = [
	client('layout-mixed-app'),
	client('layout-nopass-app'),
	client('layout-many-app'),
	client('layout-twins-app'),
	client('layout-csp-app')
];

export default {
	config
};
