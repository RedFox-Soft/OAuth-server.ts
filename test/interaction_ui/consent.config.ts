import * as errors from '../../lib/helpers/errors.ts';
import getConfig from '../default.config.js';

const config = getConfig();

export const PAYMENT_TYPE = 'https://scheme.example/payment';
export const RESOURCE = 'urn:consent:api';

/*
 * The four kinds of permission the consent screen can show come from four different mechanisms, and no
 * existing config turns all four on at once: claims need the claims parameter, per-resource scopes need
 * resource indicators *and* a resource server that offers the requested scope, and rich details need a
 * declared type. One render of all four is what proves the page groups and labels them.
 */
export const addons = {
	getResourceServerInfo(ctx: unknown, resource: string) {
		if (resource === RESOURCE) {
			return { audience: resource, scope: 'api:read api:write' };
		}
		throw new errors.InvalidTarget();
	},
	/*
	 * A rich detail is only delivered against a resolved resource server, so a request carrying
	 * authorization_details and no `resource` needs a default — otherwise the request fails with
	 * invalid_target before the consent prompt is ever reached (the same reason rar.config.ts has one).
	 * An array when defaulting for an authorization request; a single value when `oneOf` is supplied.
	 */
	defaultResource(ctx: unknown, client: unknown, oneOf?: string[]) {
		if (oneOf) {
			return oneOf[0];
		}
		return [RESOURCE];
	}
};

export const ApplicationConfig = {
	// `billing` is a supported scope with no friendly label, which is the case that renders its own token
	// twice today — and the one nobody listed, because it is neither a claim nor a resource scope.
	scopes: ['openid', 'offline_access', 'billing'],
	'claimsParameter.enabled': true,
	'resourceIndicators.enabled': true,
	'richAuthorizationRequests.enabled': true,
	'richAuthorizationRequests.types': {
		[PAYMENT_TYPE]: {
			label: 'Initiate a payment',
			fields: {
				actions: { required: true, allowed: ['initiate', 'status'] },
				locations: {},
				identifier: { required: false }
			}
		}
	}
};

export const clients = [
	{
		clientId: 'consent-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb'],
		clientName: 'Consent Test Client',
		/*
		 * `billing` reaches the prompt as a supported scope with no friendly label — the case that
		 * renders its own token twice today. A resource scope (`api:read`) is deliberately NOT listed:
		 * client metadata is validated against the AS's own scope set, and a resource server's scopes are
		 * not in it. It travels on the request instead, where the resource server vouches for it.
		 */
		scope: 'openid profile email billing',
		authorization_details_types: [PAYMENT_TYPE]
	}
];

export default {
	config
};
