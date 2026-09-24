import { InvalidTarget } from './errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { useGrantedResource, defaultResource } from '../addon/index.js';
import type { OIDCContext } from './oidc_context.ts';
import type { TokenParams } from 'lib/actions/token.js';
import type { AuthorizationCode } from 'lib/models/authorization_code.js';
import type { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import type { DeviceCode } from 'lib/models/device_code.js';
import type { RefreshToken } from 'lib/models/refresh_token.js';

// The artifact a token request redeems, which records the resources it was granted for.
type Redeemed =
	| AuthorizationCode
	| BackchannelAuthenticationRequest
	| DeviceCode
	| RefreshToken;

export default async function resolveResource(
	oidc: OIDCContext<TokenParams>,
	model: Redeemed,
	_config?: unknown,
	scopes: Set<string> = model.scopes
): Promise<string | undefined> {
	let resource: string | string[] | undefined = undefined;
	if (ApplicationConfig['resourceIndicators.enabled']) {
		switch (true) {
			case !!oidc.params.resource:
				resource = oidc.params.resource;
				break;
			case !model.payload.resource:
			case Array.isArray(model.payload.resource) &&
				model.payload.resource.length === 0:
				break;
			case model.payload.resource && !!(await useGrantedResource(oidc, model)):
			case !oidc.params.resource &&
				(!ApplicationConfig['userinfo.enabled'] || !scopes.has('openid')):
				resource = model.payload.resource;
				break;
		}

		if (Array.isArray(resource)) {
			resource = await defaultResource(oidc, oidc.client, resource);
		}

		if (Array.isArray(resource)) {
			throw new InvalidTarget(
				'only a single resource indicator value must be requested/resolved during Access Token Request'
			);
		}

		if (resource && !model.resourceIndicators.has(resource)) {
			throw new InvalidTarget();
		}
	}
	return resource;
}
