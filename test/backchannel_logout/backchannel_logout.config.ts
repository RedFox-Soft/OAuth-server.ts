import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { backchannelLogout: { enabled: true } });

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://client.example.com/cb'],
			backchannel_logout_uri: 'https://client.example.com/backchannel_logout',
			backchannel_logout_session_required: true
		},
		{
			clientId: 'second-client',
			clientSecret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://second-client.example.com/cb'],
			backchannel_logout_uri:
				'https://second-client.example.com/backchannel_logout',
			backchannel_logout_session_required: true
		},
		{
			clientId: 'no-sid',
			clientSecret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://no-sid.example.com/cb'],
			backchannel_logout_uri: 'https://no-sid.example.com/backchannel_logout'
			// backchannel_logout_session_required: false,
		}
	]
};
