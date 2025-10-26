import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	deviceFlow: { enabled: true },
	backchannelLogout: { enabled: true },
	claimsParameter: { enabled: true },
	rpInitiatedLogout: { enabled: false }
});

export default {
	config,
	clients: [
		{
			clientId: 'client',
			grantTypes: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'refresh_token'
			],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'none',
			applicationType: 'native'
		},
		{
			clientId: 'client-other',
			grantTypes: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'refresh_token'
			],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'none',
			applicationType: 'native'
		},
		{
			clientId: 'client-not-allowed',
			token_endpoint_auth_method: 'none',
			grantTypes: [],
			redirectUris: [],
			responseTypes: []
		},
		{
			clientId: 'client-backchannel',
			grantTypes: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'refresh_token'
			],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'none',
			applicationType: 'native',
			backchannel_logout_uri: 'https://rp.example.com/backchannel',
			backchannel_logout_session_required: true
		},
		{
			clientId: 'client-basic-auth',
			clientSecret: 'secret',
			grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'client_secret_basic',
			applicationType: 'native'
		}
	]
};
