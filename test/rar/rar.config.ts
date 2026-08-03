import * as errors from '../../lib/helpers/errors.ts';
import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Delivery of authorization_details onto a token requires a resolved resource server: at.payload.rar
 * is only assigned when at.resourceServer exists, and the default getResourceServerInfo throws
 * InvalidTarget. Without this override every token assertion in this suite would fail for a reason
 * unrelated to RAR — see specs/015-rar-end-to-end/research.md R22.
 */
export const addons = {
	issueRefreshToken() {
		return true;
	},
	getResourceServerInfo(ctx, resource) {
		if (resource === 'urn:rar:jwt') {
			return {
				audience: resource,
				scope: 'api:read api:write',
				accessTokenFormat: 'jwt'
			};
		}

		if (resource.startsWith('urn:rar:')) {
			return {
				audience: resource,
				scope: 'api:read api:write'
			};
		}

		throw new errors.InvalidTarget();
	},
	/*
	 * An array when defaulting for an authorization request, because the value lands in
	 * `params.resource`, which the schema types as an array — a bare string there is stored verbatim in
	 * a pushed request and then fails validation on the follow-up. A single value when `oneOf` is
	 * supplied, because the token endpoint must resolve exactly one.
	 */
	defaultResource(ctx, client, oneOf) {
		if (oneOf) {
			return oneOf[0];
		}
		return ['urn:rar:default'];
	}
};

export const PAYMENT_TYPE = 'https://scheme.example/payment';
export const OPEN_TYPE = 'https://scheme.example/open';

export const ApplicationConfig = {
	'authorization.allowOmittingSingleRegisteredRedirectUri': true,
	'richAuthorizationRequests.enabled': true,
	'richAuthorizationRequests.types': {
		[PAYMENT_TYPE]: {
			label: 'Initiate a payment',
			fields: {
				actions: { required: true, allowed: ['initiate', 'status'] },
				locations: {},
				datatypes: { allowed: ['account_information'] },
				identifier: { required: false }
			}
		},
		[OPEN_TYPE]: {
			label: 'Open-ended access',
			allowUnknownFields: true
		}
	},
	'resourceIndicators.enabled': true,
	'introspection.enabled': true,
	'par.enabled': true,
	'requestObjects.enabled': true,
	'requestObjects.request': true,
	// This suite issues refresh tokens without requesting offline_access, so the grant is advertised
	// explicitly rather than inferred from the issueRefreshToken override.
	'refreshToken.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		token_endpoint_auth_method: 'none',
		// Present so the signed-request-object case can sign with HS256.
		clientSecret: 'secret',
		'requestObject.signingAlg': 'HS256',
		redirectUris: ['https://client.example.com/cb'],
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		authorization_details_types: [PAYMENT_TYPE, OPEN_TYPE]
	},
	{
		// A client that does not require consent: the consent prompt is skipped whole, so nothing is
		// ever recorded on its grant and only Grant#getRarFiltered's trusted arm delivers its details.
		clientId: 'trusted',
		token_endpoint_auth_method: 'none',
		redirectUris: ['https://client.example.com/cb'],
		responseTypes: ['code'],
		grantTypes: ['authorization_code', 'refresh_token'],
		'consent.require': false,
		authorization_details_types: [PAYMENT_TYPE, OPEN_TYPE]
	},
	{
		// Permitted no types at all: every requested type must be refused for this client.
		clientId: 'no-types',
		token_endpoint_auth_method: 'none',
		redirectUris: ['https://client.example.com/cb'],
		responseTypes: ['code'],
		grantTypes: ['authorization_code']
	}
];

export default {
	config
};
