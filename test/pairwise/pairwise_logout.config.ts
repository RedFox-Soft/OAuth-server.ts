import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Back-channel logout for a pairwise client — spec 023, FR-007a.
 *
 * Its own config rather than an addition to test/backchannel_logout/: that suite's global-logout cases
 * POST a logout token to every visited client and mock exactly the three origins its config declares,
 * so a fourth client carrying a backchannel_logout_uri would send an unmocked request and break tests
 * that pass today.
 */

export const ApplicationConfig = {
	'backchannelLogout.enabled': true
};

export const clients = [
	{
		clientId: 'pairwise-rp',
		clientSecret: 'secret',
		subjectType: 'pairwise',
		responseTypes: ['code'],
		grantTypes: ['authorization_code'],
		redirectUris: ['https://pairwise-rp.example.com/cb'],
		backchannel_logout_uri:
			'https://pairwise-rp.example.com/backchannel_logout',
		backchannel_logout_session_required: true
	}
];

export default {
	config
};
