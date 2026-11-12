import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

/*
 * An API that requires a sign-in with a code, or a recent one (specs/130). The agent signs people in to the default
 * bucket at the root, where the specs declare two APIs: Files, which carries the requirement a case sets, and Notes,
 * which carries none. Renewals rotate, as they do for every public MCP client, so a refusal after rotation would show.
 */
export const ApplicationConfig = {
	scopes: ['openid', 'offline_access'],
	'federation.enabled': true,
	'introspection.enabled': true
};

export const addons: Partial<AddonImplementations> = {
	rotateRefreshToken() {
		return true;
	}
};

export const clients = [
	{
		clientId: 'agent',
		clientSecret: 'secret',
		client_name: 'Agent',
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://agent.acme.test/cb'],
		scope: 'openid offline_access',
		'consent.require': false
	}
];

export default {
	config
};
