import { Elysia } from 'elysia';
import defaults from '../helpers/_/defaults.ts';
import instance from '../helpers/weak_cache.ts';
import { provider } from 'lib/index.js';
import { routeNames } from 'lib/consts/param_list.js';
import { calculateDiscovery } from 'lib/configs/discoverySupport.js';
import { ApplicationConfig } from '../configs/application.js';
import { ReturnType } from '@sinclair/typebox';
import {
	authorizationEncryptionAlgValues,
	authorizationEncryptionEncValues,
	authorizationSigningAlgValues,
	clientAuthSigningAlgValues,
	idTokenEncryptionAlgValues,
	idTokenEncryptionEncValues,
	introspectionEncryptionAlgValues,
	introspectionEncryptionEncValues,
	introspectionSigningAlgValues,
	requestObjectEncryptionAlgValues,
	requestObjectEncryptionEncValues,
	requestObjectSigningAlgValues,
	userinfoEncryptionAlgValues,
	userinfoEncryptionEncValues,
	userinfoSigningAlgValues
} from 'lib/configs/jwaAlgorithms.js';

type OmitEnabled<T> = {
	[K in keyof T as K extends `${infer _}enabled` ? K : never]: T[K];
};
type discoveryKeys = keyof ReturnType<typeof calculateDiscovery>;
type featuresKeys = keyof OmitEnabled<typeof ApplicationConfig>;
const featuresKeyMap: Record<featuresKeys, Array<discoveryKeys>> = {
	'par.enabled': [
		'pushed_authorization_request_endpoint',
		'require_pushed_authorization_requests'
	],
	'dpop.enabled': ['dpop_signing_alg_values_supported'],
	'introspection.enabled': ['introspection_endpoint']
} as const;

function urls(baseUrl: string) {
	return {
		authorization_endpoint: new URL(routeNames.authorization, baseUrl).href,
		device_authorization_endpoint: new URL(
			routeNames.device_authorization,
			baseUrl
		).href,
		end_session_endpoint: new URL(routeNames.end_session, baseUrl).href,
		jwks_uri: new URL(routeNames.jwks, baseUrl).href,
		registration_endpoint: new URL(routeNames.registration, baseUrl).href,
		token_endpoint: new URL(routeNames.token, baseUrl).href,
		userinfo_endpoint: new URL(routeNames.userinfo, baseUrl).href,
		revocation_endpoint: new URL(routeNames.revocation, baseUrl).href,
		backchannel_authentication_endpoint: new URL(
			routeNames.backchannel_authentication,
			baseUrl
		).href
	};
}

export const discovery = new Elysia().get(
	'/.well-known/openid-configuration',
	function ({ request }) {
		const { configuration, features } = instance(provider);
		const url = new URL(request.url);
		url.pathname = '';
		url.search = '';
		const urlObj = urls(url.toString());

		const body = {
			acr_values_supported: configuration.acrValues.size
				? [...configuration.acrValues]
				: undefined,
			authorization_endpoint: urlObj.authorization_endpoint,
			device_authorization_endpoint: features.deviceFlow.enabled
				? urlObj.device_authorization_endpoint
				: undefined,
			claims_parameter_supported: features.claimsParameter.enabled,
			claims_supported: [...configuration.claimsSupported],

			end_session_endpoint: features.rpInitiatedLogout.enabled
				? urlObj.end_session_endpoint
				: undefined,
			grant_types_supported: [...configuration.grantTypes],
			jwks_uri: urlObj.jwks_uri,
			registration_endpoint: features.registration.enabled
				? urlObj.registration_endpoint
				: undefined,
			authorization_response_iss_parameter_supported: true,
			scopes_supported: [...configuration.scopes],
			token_endpoint_auth_methods_supported: [
				...configuration.clientAuthMethods
			],
			token_endpoint_auth_signing_alg_values_supported:
				clientAuthSigningAlgValues,
			token_endpoint: urlObj.token_endpoint,
			...calculateDiscovery()
		};

		const keys = Object.keys(featuresKeyMap) as featuresKeys[];
		keys.forEach((feature) => {
			if (ApplicationConfig[feature] === false) {
				const keys = featuresKeyMap[feature];
				keys.forEach((key: discoveryKeys) => {
					delete body[key];
				});
			}
		});

		const { requestObjects, richAuthorizationRequests } = features;

		if (features.encryption.enabled) {
			body.id_token_encryption_alg_values_supported =
				idTokenEncryptionAlgValues;
			body.id_token_encryption_enc_values_supported =
				idTokenEncryptionEncValues;
		}

		body.request_uri_parameter_supported = false;
		if (requestObjects.enabled) {
			body.request_parameter_supported = true;
			body.request_object_signing_alg_values_supported =
				requestObjectSigningAlgValues;
			body.require_signed_request_object =
				requestObjects.requireSignedRequestObject ? true : undefined;

			if (features.encryption.enabled) {
				body.request_object_encryption_alg_values_supported =
					requestObjectEncryptionAlgValues;
				body.request_object_encryption_enc_values_supported =
					requestObjectEncryptionEncValues;
			}
		}

		if (features.userinfo.enabled) {
			body.userinfo_endpoint = urlObj.userinfo_endpoint;
			if (features.jwtUserinfo.enabled) {
				body.userinfo_signing_alg_values_supported = userinfoSigningAlgValues;
				if (features.encryption.enabled) {
					body.userinfo_encryption_alg_values_supported =
						userinfoEncryptionAlgValues;
					body.userinfo_encryption_enc_values_supported =
						userinfoEncryptionEncValues;
				}
			}
		}

		if (features.jwtResponseModes.enabled) {
			body.authorization_signing_alg_values_supported =
				authorizationSigningAlgValues;

			if (features.encryption.enabled) {
				body.authorization_encryption_alg_values_supported =
					authorizationEncryptionAlgValues;
				body.authorization_encryption_enc_values_supported =
					authorizationEncryptionEncValues;
			}
		}

		if (features.jwtIntrospection.enabled) {
			body.introspection_signing_alg_values_supported =
				introspectionSigningAlgValues;
			if (features.encryption.enabled) {
				body.introspection_encryption_alg_values_supported =
					introspectionEncryptionAlgValues;
				body.introspection_encryption_enc_values_supported =
					introspectionEncryptionEncValues;
			}
		}

		if (features.revocation.enabled) {
			body.revocation_endpoint = urlObj.revocation_endpoint;
		}

		if (features.backchannelLogout.enabled) {
			body.backchannel_logout_supported = true;
			body.backchannel_logout_session_supported = true;
		}

		if (features.mTLS.enabled && features.mTLS.certificateBoundAccessTokens) {
			body.tls_client_certificate_bound_access_tokens = true;
		}

		if (features.ciba.enabled) {
			body.backchannel_authentication_endpoint =
				urlObj.backchannel_authentication_endpoint;
			body.backchannel_token_delivery_modes_supported = [
				...features.ciba.deliveryModes
			];
			body.backchannel_user_code_parameter_supported = true;
			body.backchannel_authentication_request_signing_alg_values_supported =
				requestObjects.enabled
					? requestObjectSigningAlgValues.filter((alg) => !alg.startsWith('HS'))
					: undefined;
		}

		if (richAuthorizationRequests.enabled) {
			body.authorization_details_types_supported = Object.keys(
				richAuthorizationRequests.types
			);
		}

		Object.keys(body).forEach((key) => {
			if (
				key in body &&
				key !== 'request_uri_parameter_supported' &&
				body[key] === false
			) {
				delete body[key];
			}
		});

		defaults(body, configuration.discovery);
		return body;
	}
);
