import merge from 'lodash/merge.js';

import * as errors from '../../lib/helpers/errors.ts';
import getConfig from '../default.config.js';
import { Grant } from 'lib/models/grant.js';
import { grantFlags } from './grant_flags.ts';

const config = getConfig();

merge(config, {
	issueRefreshToken() {
		return true;
	},
	features: {
		ciba: {
			processLoginHint(ctx, loginHint) {
				return loginHint;
			},
			validateBindingMessage() {},
			validateRequestContext() {},
			verifyUserCode() {},
			async triggerAuthenticationDevice(ctx, request) {
				const grant = new Grant({
					clientId: request.payload.clientId,
					accountId: request.payload.accountId
				});
				grant.addOIDCScope(ctx.oidc.requestParamScopes);

				const resources = Array.isArray(request.payload.resource)
					? request.payload.resource
					: [request.payload.resource];

				for (const resource of resources) {
					grant.addResourceScope(resource, request.payload.scope);
				}

				await grant.save();
				return ctx.oidc.provider.backchannelResult(request, grant.jti);
			}
		},
		resourceIndicators: {
			async useGrantedResource() {
				return grantFlags.useGranted;
			},
			getResourceServerInfo(ctx, resource) {
				if (resource.includes('wl')) {
					return {
						audience: resource,
						scope: 'api:read api:write'
					};
				}

				throw new errors.InvalidTarget();
			},
			defaultResource() {
				if (grantFlags.noDefault) {
					return undefined;
				}

				return 'urn:wl:default';
			}
		}
	}
});

export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	'introspection.enabled': true,
	'deviceFlow.enabled': true,
	'ciba.enabled': true,
	'resourceIndicators.enabled': true
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			token_endpoint_auth_method: 'none',
			redirectUris: ['https://client.example.com/cb'],
			responseTypes: ['code'],
			backchannel_token_delivery_mode: 'poll',
			grantTypes: [
				'refresh_token',
				'client_credentials',
				'authorization_code',
				'urn:ietf:params:oauth:grant-type:device_code',
				'urn:openid:params:grant-type:ciba'
			]
		}
	]
};
