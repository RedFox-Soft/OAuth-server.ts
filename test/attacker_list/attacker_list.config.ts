import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The list on, with attack reporting on as it requires. The rate limit is off for the reason
 * test/attack_reports/attack_reports.config.ts gives: these cases send many sign-ins from one address, and the strict
 * limit would answer 429 before the list is ever consulted.
 */
export const ApplicationConfig = {
	'rateLimit.enabled': false,
	'clientAddress.source': 'automatic',
	'attackReports.enabled': true,
	'attackerList.enabled': true,
	'telemetry.enabled': true
};

export const clients = [
	{
		clientId: 'guessing-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/guessing/callback']
	}
];

export default {
	config
};
