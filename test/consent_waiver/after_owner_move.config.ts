import getConfig from '../default.config.js';

const config = getConfig();

/*
 * One client that skips consent. Seeded by the spec into a bucket of its own, so the client signs that
 * bucket's users in.
 */
export const clients = [
	{
		clientId: 'moving-app',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://moving.example.com/cb'],
		'consent.require': false
	}
];

export default {
	config
};
