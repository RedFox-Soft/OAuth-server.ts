import * as errors from '../../lib/helpers/errors.ts';
import getConfig from '../default.config.js';
import { Grant } from 'lib/models/grant.js';
import { backchannelResult } from 'lib/actions/authorization/backchannel_result.js';
import { grantFlags } from './grant_flags.ts';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

export const addons: Partial<AddonImplementations> = {
	issueRefreshToken() {
		return true;
	},
	processLoginHint(oidc, loginHint) {
		return loginHint;
	},
	validateBindingMessage() {},
	validateRequestContext() {},
	verifyUserCode() {},
	async triggerAuthenticationDevice(oidc, request) {
		const grant = new Grant({
			clientId: request.payload.clientId,
			accountId: request.payload.accountId
		});
		grant.addOIDCScope(oidc.requestParamScopes);

		const { resource, scope = '' } = request.payload;
		for (const indicator of [resource ?? []].flat()) {
			grant.addResourceScope(indicator, scope);
		}

		await grant.save();
		return backchannelResult(request, grant.jti);
	},
	async useGrantedResource() {
		return grantFlags.useGranted;
	},
	getResourceServerInfo(oidc, resource) {
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
};

export const ApplicationConfig = {
	'authorization.allowOmittingSingleRegisteredRedirectUri': true,
	'clientCredentials.enabled': true,
	'introspection.enabled': true,
	'deviceFlow.enabled': true,
	'ciba.enabled': true,
	'resourceIndicators.enabled': true,
	// This suite issues refresh tokens (issueRefreshToken override returns true)
	// without requesting offline_access, so advertise the grant explicitly now
	// that it is no longer inferred from a customized issueRefreshToken (FR-016).
	'refreshToken.enabled': true
};

export const clients = [
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
];

export default {
	config
};
