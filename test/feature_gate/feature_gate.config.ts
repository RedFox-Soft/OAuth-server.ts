import getConfig from '../default.config.js';

const config = getConfig();

// Every gated capability starts off — including the two that default to on — so each spec turns on
// exactly the one it is exercising. The point of this feature is that "off" means unreachable, so the
// baseline has to be genuinely off.
export const ApplicationConfig = {
	'userinfo.enabled': false,
	'rpInitiatedLogout.enabled': false
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	},
	// Permitted the device-code and CIBA grants by its own metadata, so the specs can prove the
	// server flag is consulted first (FR-008).
	{
		clientId: 'client-device',
		clientSecret: 'secret',
		grantTypes: [
			'urn:ietf:params:oauth:grant-type:device_code',
			'urn:openid:params:grant-type:ciba'
		],
		responseTypes: [],
		redirectUris: [],
		backchannelTokenDeliveryMode: 'poll'
	}
];

export default {
	config
};
