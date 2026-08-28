import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Deliberately tiny allowances. Every enforcement case drives an origin to its edge and one past it,
 * so the production default of sixty per minute would mean sixty requests per assertion for no extra
 * coverage — and would make a suite that is meant to be instant depend on how fast the runner is.
 *
 * The three classes get three different numbers on purpose: a spec that exhausts one and then finds
 * another still open is only proving class isolation if the two could not have been the same counter.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': true,
	'rateLimit.trustedProxy': true,
	'rateLimit.maxTrackedOrigins': 100,
	'rateLimit.strict.max': 3,
	'rateLimit.strict.windowSeconds': 60,
	'rateLimit.ordinary.max': 5,
	'rateLimit.ordinary.windowSeconds': 60,
	'rateLimit.public.max': 8,
	'rateLimit.public.windowSeconds': 60
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
