import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';
import { Grant } from 'lib/models/grant.js';

const config = getConfig();

merge(config.features, {
	clientCredentials: { enabled: true },
	introspection: { enabled: true },
	deviceFlow: { enabled: true },
	requestObjects: { enabled: true },
	ciba: {
		enabled: true,
		processLoginHint(ctx, loginHint) {
			return loginHint;
		},
		validateBindingMessage() {},
		validateRequestContext() {},
		verifyUserCode() {},
		async triggerAuthenticationDevice(ctx, request) {
			const grant = new Grant({
				clientId: request.clientId,
				accountId: request.accountId
			});
			grant.addOIDCScope(ctx.oidc.requestParamScopes);
			await grant.save();
			return ctx.oidc.provider.backchannelResult(request, grant.jti);
		}
	}
});

export const ApplicationConfig = {
	'par.enabled': true,
	'dpop.enabled': true,
	'dpop.nonceSecret': Buffer.alloc(32, 0)
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			grantTypes: [
				'authorization_code',
				'refresh_token',
				'urn:ietf:params:oauth:grant-type:device_code',
				'urn:openid:params:grant-type:ciba',
				'client_credentials'
			],
			responseTypes: ['code'],
			backchannel_token_delivery_mode: 'poll',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-none',
			grantTypes: [
				'authorization_code',
				'urn:ietf:params:oauth:grant-type:device_code',
				'urn:openid:params:grant-type:ciba',
				'refresh_token'
			],
			responseTypes: ['code'],
			backchannel_token_delivery_mode: 'poll',
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none'
		}
	]
};
