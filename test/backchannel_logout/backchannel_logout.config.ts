import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { backchannelLogout: { enabled: true } });

export default {
	config,
	clients: [
		{
			clientId: 'client',
			client_secret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirect_uris: ['https://client.example.com/cb'],
			backchannel_logout_uri: 'https://client.example.com/backchannel_logout',
			backchannel_logout_session_required: true
		},
		{
			clientId: 'second-client',
			client_secret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirect_uris: ['https://second-client.example.com/cb'],
			backchannel_logout_uri:
				'https://second-client.example.com/backchannel_logout',
			backchannel_logout_session_required: true
		},
		{
			clientId: 'no-sid',
			client_secret: 'secret',
			response_types: ['code'],
			grant_types: ['authorization_code', 'refresh_token'],
			redirect_uris: ['https://no-sid.example.com/cb'],
			backchannel_logout_uri: 'https://no-sid.example.com/backchannel_logout'
			// backchannel_logout_session_required: false,
		}
	]
};
