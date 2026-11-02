import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Connected services (specs/117): a person connects accounts at other services from their account page. The
 * specs declare the services on the default bucket and stub each provider, so the harness needs no client of
 * its own: the account page signs people in through the client it synthesizes.
 */
export const ApplicationConfig = {
	scopes: ['openid']
};

export const clients = [];

export default {
	config
};
