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
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'refresh_token'
			],
			response_types: [],
			redirect_uris: [],
			token_endpoint_auth_method: 'none',
			application_type: 'native'
		},
		{
			clientId: 'client-other',
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'refresh_token'
			],
			response_types: [],
			redirect_uris: [],
			token_endpoint_auth_method: 'none',
			application_type: 'native'
		},
		{
			clientId: 'client-not-allowed',
			token_endpoint_auth_method: 'none',
			grant_types: [],
			redirect_uris: [],
			response_types: []
		},
		{
			clientId: 'client-backchannel',
			grant_types: [
				'urn:ietf:params:oauth:grant-type:device_code',
				'refresh_token'
			],
			response_types: [],
			redirect_uris: [],
			token_endpoint_auth_method: 'none',
			application_type: 'native',
			backchannel_logout_uri: 'https://rp.example.com/backchannel',
			backchannel_logout_session_required: true
		},
		{
			clientId: 'client-basic-auth',
			client_secret: 'secret',
			grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
			response_types: [],
			redirect_uris: [],
			token_endpoint_auth_method: 'client_secret_basic',
			application_type: 'native'
		}
	]
};
