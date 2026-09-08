import { ISSUER } from 'lib/configs/env.js';
import { routeNames } from 'lib/consts/param_list.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { ApplicationConfig } from './application.js';
import { isPlainObject } from '../helpers/_/object.js';
import {
	authorizationEncryptionAlgValues,
	authorizationEncryptionEncValues,
	authorizationSigningAlgValues,
	clientAuthSigningAlgValues,
	dPoPSigningAlgValues,
	idTokenEncryptionAlgValues,
	idTokenEncryptionEncValues,
	idTokenSigningAlgValues,
	introspectionEncryptionAlgValues,
	introspectionEncryptionEncValues,
	introspectionSigningAlgValues,
	requestObjectEncryptionAlgValues,
	requestObjectEncryptionEncValues,
	requestObjectSigningAlgValues,
	userinfoEncryptionAlgValues,
	userinfoEncryptionEncValues,
	userinfoSigningAlgValues
} from './jwaAlgorithms.js';

type Config = typeof ApplicationConfig;

// The collection-type discovery values are derived here from the live ApplicationConfig
// so a runtime change is reflected on the next fetch. These rules intentionally mirror
// lib/configs/configuration.ts (collectScopes/collectClaims/collectGrantTypes/checkAuthMethods);
// the parity fixture test guards against divergence.

function deriveAcrValues(config: Config): string[] {
	return [...config.acrValues];
}

function deriveScopes(config: Config): string[] {
	const scopes = new Set<string>(config.scopes);
	for (const [key, value] of Object.entries(config.claims)) {
		if (isPlainObject(value) || Array.isArray(value)) {
			scopes.add(key);
		}
	}
	return [...scopes];
}

function deriveGrantTypes(config: Config): string[] {
	const grantTypes = new Set<string>(['authorization_code']);
	if (config.scopes.includes('offline_access')) {
		grantTypes.add('refresh_token');
	}
	if (config['clientCredentials.enabled']) {
		grantTypes.add('client_credentials');
	}
	if (config['deviceFlow.enabled']) {
		grantTypes.add('urn:ietf:params:oauth:grant-type:device_code');
	}
	if (config['ciba.enabled']) {
		grantTypes.add('urn:openid:params:grant-type:ciba');
	}
	return [...grantTypes];
}

function deriveClaimsSupported(config: Config): string[] {
	// Clone so the shared ApplicationConfig.claims is never mutated by the unpack/prune below.
	const claims: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(config.claims)) {
		if (Array.isArray(value)) {
			claims[key] = value.reduce<Record<string, null>>((acc, claim) => {
				acc[claim] = null;
				return acc;
			}, {});
		} else if (isPlainObject(value)) {
			claims[key] = { ...value };
		} else {
			claims[key] = value;
		}
	}

	const openid = claims.openid;
	if (isPlainObject(openid) && !('sub' in openid)) {
		openid.sub = null;
	}

	// acr is only advertised when the server declares acr values.
	if (!deriveAcrValues(config).length) {
		delete claims.acr;
	}

	const supported = new Set<string>();
	for (const scope of deriveScopes(config)) {
		const scopeClaims = claims[scope];
		if (isPlainObject(scopeClaims)) {
			Object.keys(scopeClaims).forEach((claim) => supported.add(claim));
		}
	}
	for (const [key, value] of Object.entries(claims)) {
		if (value === null) supported.add(key);
	}
	return [...supported];
}

function deriveClientAuthMethods(config: Config): string[] {
	const methods = new Set<string>(config.clientAuthMethods);
	if (config['mTLS.enabled'] && config['mTLS.tlsClientAuth']) {
		methods.add('tls_client_auth');
	}
	if (config['mTLS.enabled'] && config['mTLS.selfSignedTlsClientAuth']) {
		methods.add('self_signed_tls_client_auth');
	}
	return [...methods];
}

function endpoint(route: string): string {
	return new URL(route, ISSUER).href;
}

// Builds the full candidate discovery document as if every feature were enabled, reading all
// values live from ApplicationConfig. The request handler prunes disabled features via
// featuresKeyMap and applies operator discovery overrides.
export function calculateDiscovery() {
	const config = ApplicationConfig;
	const acrValues = deriveAcrValues(config);

	return {
		issuer: ISSUER,
		authorization_endpoint: endpoint(routeNames.authorization),
		token_endpoint: endpoint(routeNames.token),
		jwks_uri: endpoint(routeNames.jwks),
		userinfo_endpoint: endpoint(routeNames.userinfo),
		registration_endpoint: endpoint(routeNames.registration),
		device_authorization_endpoint: endpoint(routeNames.device_authorization),
		end_session_endpoint: endpoint(routeNames.end_session),
		revocation_endpoint: endpoint(routeNames.revocation),
		introspection_endpoint: endpoint(routeNames.introspect),
		pushed_authorization_request_endpoint: endpoint(
			routeNames.pushed_authorization_request
		),
		backchannel_authentication_endpoint: endpoint(
			routeNames.backchannel_authentication
		),

		scopes_supported: deriveScopes(config),
		claims_supported: deriveClaimsSupported(config),
		grant_types_supported: deriveGrantTypes(config),
		token_endpoint_auth_methods_supported: deriveClientAuthMethods(config),
		acr_values_supported: acrValues.length ? acrValues : undefined,

		response_types_supported: ['none', 'code'],
		response_modes_supported: config['responseMode.jwt.enabled']
			? ['form_post', 'query', 'jwt', 'query.jwt', 'form_post.jwt']
			: ['form_post', 'query'],
		subject_types_supported: ['public', 'pairwise'],
		code_challenge_methods_supported: ['S256'],
		id_token_signing_alg_values_supported: idTokenSigningAlgValues,
		token_endpoint_auth_signing_alg_values_supported:
			clientAuthSigningAlgValues,
		authorization_response_iss_parameter_supported: true,
		/*
		 * Emitted only while the capability is on, and the conditionality is the point. A client is told
		 * to check for this member before presenting a URL-shaped `client_id` and to fall back otherwise
		 * — so advertising it while the server would refuse the mechanism converts a working fallback
		 * into a guaranteed failure.
		 */
		client_id_metadata_document_supported: config[
			'clientIdMetadataDocument.enabled'
		]
			? true
			: undefined,
		request_uri_parameter_supported: false,

		claims_parameter_supported: true,
		require_pushed_authorization_requests:
			ClientDefaults['authorization.requirePushedAuthorizationRequests'],
		dpop_signing_alg_values_supported: dPoPSigningAlgValues,

		id_token_encryption_alg_values_supported: idTokenEncryptionAlgValues,
		id_token_encryption_enc_values_supported: idTokenEncryptionEncValues,

		request_parameter_supported: true,
		request_object_signing_alg_values_supported: requestObjectSigningAlgValues,
		require_signed_request_object: config[
			'requestObjects.requireSignedRequestObject'
		]
			? true
			: undefined,
		request_object_encryption_alg_values_supported:
			requestObjectEncryptionAlgValues,
		request_object_encryption_enc_values_supported:
			requestObjectEncryptionEncValues,

		userinfo_signing_alg_values_supported: userinfoSigningAlgValues,
		userinfo_encryption_alg_values_supported: userinfoEncryptionAlgValues,
		userinfo_encryption_enc_values_supported: userinfoEncryptionEncValues,

		authorization_signing_alg_values_supported: authorizationSigningAlgValues,
		authorization_encryption_alg_values_supported:
			authorizationEncryptionAlgValues,
		authorization_encryption_enc_values_supported:
			authorizationEncryptionEncValues,

		introspection_signing_alg_values_supported: introspectionSigningAlgValues,
		introspection_encryption_alg_values_supported:
			introspectionEncryptionAlgValues,
		introspection_encryption_enc_values_supported:
			introspectionEncryptionEncValues,

		backchannel_logout_supported: true,
		backchannel_logout_session_supported: true,

		tls_client_certificate_bound_access_tokens: config[
			'mTLS.certificateBoundAccessTokens'
		]
			? true
			: undefined,

		backchannel_token_delivery_modes_supported: [
			...config['ciba.deliveryModes']
		],
		backchannel_user_code_parameter_supported: true,
		backchannel_authentication_request_signing_alg_values_supported: config[
			'requestObjects.enabled'
		]
			? requestObjectSigningAlgValues.filter((alg) => !alg.startsWith('HS'))
			: undefined,

		authorization_details_types_supported: Object.keys(
			config['richAuthorizationRequests.types']
		)
	};
}

type OmitEnabled<T> = {
	[K in keyof T as K extends `${string}enabled` ? K : never]: T[K];
};
type DiscoveryKey = keyof ReturnType<typeof calculateDiscovery>;
export type FeatureFlagKey = keyof OmitEnabled<typeof ApplicationConfig>;

/*
 * Which of the two metadata documents a member belongs to, and why.
 *
 * The reason is a field rather than a comment because the reason is the contestable part. Membership
 * is decided by the REGISTERING SPECIFICATION, never by presence in the IANA OAuth Authorization
 * Server Metadata registry: RFC 8414 §2 invites other specifications into that registry and OpenID
 * Connect Discovery accepted, so every member below is registered there and the check would pass
 * vacuously for all of them.
 *
 * `coherentWith` marks the twelve members that an OpenID specification registered but that an
 * OAuth-registered member cannot be acted on without — advertising a requirement for signed request
 * objects while naming no signing algorithm, or a CIBA grant with no endpoint to reach it, is not a
 * usable document. The guard in test/discovery/metadata_classification.spec.ts checks those targets
 * still exist and are themselves `both`, so the justification cannot outlive what it depends on.
 */
export type MetadataAudience =
	| { audience: 'oidc' }
	| { audience: 'both'; registeredBy: string }
	| { audience: 'both'; coherentWith: DiscoveryKey };

export const metadataClassification: Record<DiscoveryKey, MetadataAudience> = {
	// RFC 8414 base registry.
	issuer: { audience: 'both', registeredBy: 'RFC 8414' },
	authorization_endpoint: { audience: 'both', registeredBy: 'RFC 8414' },
	token_endpoint: { audience: 'both', registeredBy: 'RFC 8414' },
	jwks_uri: { audience: 'both', registeredBy: 'RFC 8414' },
	registration_endpoint: { audience: 'both', registeredBy: 'RFC 8414' },
	revocation_endpoint: { audience: 'both', registeredBy: 'RFC 8414' },
	introspection_endpoint: { audience: 'both', registeredBy: 'RFC 8414' },
	device_authorization_endpoint: { audience: 'both', registeredBy: 'RFC 8414' },
	scopes_supported: { audience: 'both', registeredBy: 'RFC 8414' },
	grant_types_supported: { audience: 'both', registeredBy: 'RFC 8414' },
	response_types_supported: { audience: 'both', registeredBy: 'RFC 8414' },
	response_modes_supported: { audience: 'both', registeredBy: 'RFC 8414' },
	token_endpoint_auth_methods_supported: {
		audience: 'both',
		registeredBy: 'RFC 8414'
	},
	token_endpoint_auth_signing_alg_values_supported: {
		audience: 'both',
		registeredBy: 'RFC 8414'
	},
	code_challenge_methods_supported: {
		audience: 'both',
		registeredBy: 'RFC 8414'
	},

	// Registered by another IETF OAuth RFC.
	pushed_authorization_request_endpoint: {
		audience: 'both',
		registeredBy: 'RFC 9126'
	},
	require_pushed_authorization_requests: {
		audience: 'both',
		registeredBy: 'RFC 9126'
	},
	dpop_signing_alg_values_supported: {
		audience: 'both',
		registeredBy: 'RFC 9449'
	},
	authorization_response_iss_parameter_supported: {
		audience: 'both',
		registeredBy: 'RFC 9207'
	},
	/*
	 * Registered by an IETF draft rather than a published RFC, which is why the value names the draft
	 * revision: the member's spelling is only as stable as the document that defines it, and a reader
	 * checking this against a future RFC needs to know which text it was written from. OAuth-side
	 * regardless of that — it describes how a client identifies itself to the authorization server,
	 * which OpenID Connect Discovery has nothing to say about.
	 */
	client_id_metadata_document_supported: {
		audience: 'both',
		registeredBy: 'draft-ietf-oauth-client-id-metadata-document-00'
	},
	tls_client_certificate_bound_access_tokens: {
		audience: 'both',
		registeredBy: 'RFC 8705'
	},
	authorization_details_types_supported: {
		audience: 'both',
		registeredBy: 'RFC 9396'
	},
	require_signed_request_object: { audience: 'both', registeredBy: 'RFC 9101' },
	introspection_signing_alg_values_supported: {
		audience: 'both',
		registeredBy: 'RFC 9701'
	},
	introspection_encryption_alg_values_supported: {
		audience: 'both',
		registeredBy: 'RFC 9701'
	},
	introspection_encryption_enc_values_supported: {
		audience: 'both',
		registeredBy: 'RFC 9701'
	},

	// JWT-secured authorization requests: OIDC Discovery registered these, but RFC 9101 makes the
	// facility an OAuth one and registers require_signed_request_object itself.
	request_parameter_supported: {
		audience: 'both',
		coherentWith: 'require_signed_request_object'
	},
	request_uri_parameter_supported: {
		audience: 'both',
		coherentWith: 'require_signed_request_object'
	},
	request_object_signing_alg_values_supported: {
		audience: 'both',
		coherentWith: 'require_signed_request_object'
	},
	request_object_encryption_alg_values_supported: {
		audience: 'both',
		coherentWith: 'require_signed_request_object'
	},
	request_object_encryption_enc_values_supported: {
		audience: 'both',
		coherentWith: 'require_signed_request_object'
	},

	// CIBA is an OpenID Foundation specification, but grant_types_supported advertises its grant.
	backchannel_authentication_endpoint: {
		audience: 'both',
		coherentWith: 'grant_types_supported'
	},
	backchannel_token_delivery_modes_supported: {
		audience: 'both',
		coherentWith: 'grant_types_supported'
	},
	backchannel_user_code_parameter_supported: {
		audience: 'both',
		coherentWith: 'grant_types_supported'
	},
	backchannel_authentication_request_signing_alg_values_supported: {
		audience: 'both',
		coherentWith: 'grant_types_supported'
	},

	// JARM is an OpenID Foundation specification, but response_modes_supported lists its jwt forms.
	authorization_signing_alg_values_supported: {
		audience: 'both',
		coherentWith: 'response_modes_supported'
	},
	authorization_encryption_alg_values_supported: {
		audience: 'both',
		coherentWith: 'response_modes_supported'
	},
	authorization_encryption_enc_values_supported: {
		audience: 'both',
		coherentWith: 'response_modes_supported'
	},

	// OpenID Connect only: no OAuth-registered member this server emits refers to any of these.
	userinfo_endpoint: { audience: 'oidc' },
	userinfo_signing_alg_values_supported: { audience: 'oidc' },
	userinfo_encryption_alg_values_supported: { audience: 'oidc' },
	userinfo_encryption_enc_values_supported: { audience: 'oidc' },
	id_token_signing_alg_values_supported: { audience: 'oidc' },
	id_token_encryption_alg_values_supported: { audience: 'oidc' },
	id_token_encryption_enc_values_supported: { audience: 'oidc' },
	subject_types_supported: { audience: 'oidc' },
	acr_values_supported: { audience: 'oidc' },
	claims_supported: { audience: 'oidc' },
	claims_parameter_supported: { audience: 'oidc' },
	end_session_endpoint: { audience: 'oidc' },
	backchannel_logout_supported: { audience: 'oidc' },
	backchannel_logout_session_supported: { audience: 'oidc' }
};

export const featuresKeyMap: Partial<Record<FeatureFlagKey, DiscoveryKey[]>> = {
	'par.enabled': [
		'pushed_authorization_request_endpoint',
		'require_pushed_authorization_requests'
	],
	'dpop.enabled': ['dpop_signing_alg_values_supported'],
	'introspection.enabled': ['introspection_endpoint'],
	'claimsParameter.enabled': ['claims_parameter_supported'],
	'deviceFlow.enabled': ['device_authorization_endpoint'],
	'rpInitiatedLogout.enabled': ['end_session_endpoint'],
	'registration.enabled': ['registration_endpoint'],
	'revocation.enabled': ['revocation_endpoint'],
	'backchannelLogout.enabled': [
		'backchannel_logout_supported',
		'backchannel_logout_session_supported'
	],
	'mTLS.enabled': ['tls_client_certificate_bound_access_tokens'],
	'ciba.enabled': [
		'backchannel_authentication_endpoint',
		'backchannel_token_delivery_modes_supported',
		'backchannel_user_code_parameter_supported',
		'backchannel_authentication_request_signing_alg_values_supported'
	],
	'richAuthorizationRequests.enabled': [
		'authorization_details_types_supported'
	],
	'encryption.enabled': [
		'id_token_encryption_alg_values_supported',
		'id_token_encryption_enc_values_supported',
		'request_object_encryption_alg_values_supported',
		'request_object_encryption_enc_values_supported',
		'userinfo_encryption_alg_values_supported',
		'userinfo_encryption_enc_values_supported',
		'authorization_encryption_alg_values_supported',
		'authorization_encryption_enc_values_supported',
		'introspection_encryption_alg_values_supported',
		'introspection_encryption_enc_values_supported'
	],
	'requestObjects.enabled': [
		'request_parameter_supported',
		'request_object_signing_alg_values_supported',
		'require_signed_request_object',
		'request_object_encryption_alg_values_supported',
		'request_object_encryption_enc_values_supported'
	],
	'userinfo.enabled': [
		'userinfo_endpoint',
		'userinfo_signing_alg_values_supported',
		'userinfo_encryption_alg_values_supported',
		'userinfo_encryption_enc_values_supported'
	],
	'jwtUserinfo.enabled': [
		'userinfo_signing_alg_values_supported',
		'userinfo_encryption_alg_values_supported',
		'userinfo_encryption_enc_values_supported'
	],
	'responseMode.jwt.enabled': [
		'authorization_signing_alg_values_supported',
		'authorization_encryption_alg_values_supported',
		'authorization_encryption_enc_values_supported'
	],
	'jwtIntrospection.enabled': [
		'introspection_signing_alg_values_supported',
		'introspection_encryption_alg_values_supported',
		'introspection_encryption_enc_values_supported'
	]
};
