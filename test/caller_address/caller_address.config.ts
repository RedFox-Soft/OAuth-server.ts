import getConfig from '../default.config.js';

const config = getConfig();

/*
 * A strict allowance of three, so "limited as one caller" is four requests, and a source each spec
 * overrides per case: the subject here is which address a request is attributed to under each choice.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': true,
	'rateLimit.strict.max': 3,
	'rateLimit.strict.windowSeconds': 60,
	'errorStore.enabled': true,
	'errorStore.originCaptureLevel': 'full' as const
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
