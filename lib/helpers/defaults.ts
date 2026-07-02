import { mustChange } from '../addon/_warn.ts';
import { clientBasedCORS } from '../addon/cors.ts';
import {
	certificateAuthorized,
	certificateSubjectMatches
} from '../addon/mtls.ts';
import {
	deviceInfo,
	userCodeInputSource,
	userCodeConfirmSource,
	successSource
} from '../addon/interactions.ts';
import { renderError } from '../addon/error.ts';
import { introspectionAllowedPolicy } from '../addon/introspection.ts';
import {
	idFactory,
	secretFactory,
	expiresWithSession,
	issueRefreshToken,
	pairwiseIdentifier,
	rotateRefreshToken
} from '../addon/tokens.ts';
import {
	defaultResource,
	useGrantedResource,
	getResourceServerInfo
} from '../addon/resources.ts';
import { findAccount, loadExistingGrant } from '../addon/account.ts';
import {
	sectorIdentifierUriValidate,
	assertClaimsParameter,
	assertJwtClaimsAndHeader
} from '../addon/claims.ts';
import {
	processLoginHintToken,
	processLoginHint,
	verifyUserCode,
	validateBindingMessage,
	validateRequestContext,
	triggerAuthenticationDevice
} from '../addon/ciba.ts';
import { base as defaultPolicy } from './interaction_policy/index.ts';

function makeDefaults() {
	const defaults = {
		/*
		 * clientBasedCORS
		 *
		 * description: Function used to check whether a given CORS request should be allowed
		 *   based on the request's client.
		 */
		clientBasedCORS,

		/*
		 * clients
		 *
		 * description: Array of objects representing client metadata. These clients are referred to as
		 * static, they don't expire, never reload, are always available.
		 */
		clients: [],

		/*
		 * clientDefaults
		 *
		 * description: Default client metadata to be assigned when unspecified by the client metadata,
		 * e.g. during Dynamic Client Registration or for statically configured clients.
		 */
		clientDefaults: {
			id_token_signed_response_alg: 'RS256',
			token_endpoint_auth_method: 'client_secret_basic'
		},

		/*
		 * conformIdTokenClaims
		 *
		 * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
		 */
		conformIdTokenClaims: true,

		/*
		 * loadExistingGrant
		 *
		 * description: Helper function used to load existing but also just in time pre-established Grants
		 * to attempt to resolve an Authorization Request with.
		 */
		loadExistingGrant,

		/*
		 * allowOmittingSingleRegisteredRedirectUri
		 *
		 * title: Allow omitting the redirect_uri parameter when only a single one is registered for a client.
		 */
		allowOmittingSingleRegisteredRedirectUri: true,

		/*
		 * discovery
		 *
		 * description: Pass additional properties to this object to extend the discovery document
		 */
		discovery: {
			claim_types_supported: ['normal'],
			claims_locales_supported: undefined,
			display_values_supported: undefined,
			op_policy_uri: undefined,
			op_tos_uri: undefined,
			service_documentation: undefined,
			ui_locales_supported: undefined
		},

		/*
		 * features
		 *
		 * description: Deployment-specific helper functions for each feature. Feature enable flags and
		 *   sub-options are NOT here — they are owned by ApplicationConfig and read from it directly.
		 */
		features: {
			/*
			 * features.ciba.* — CIBA helper functions
			 *
			 * triggerAuthenticationDevice, validateBindingMessage, validateRequestContext,
			 * processLoginHintToken, processLoginHint, verifyUserCode
			 */
			ciba: {
				triggerAuthenticationDevice,
				validateBindingMessage,
				validateRequestContext,
				processLoginHintToken,
				processLoginHint,
				verifyUserCode
			},

			/*
			 * features.mTLS.* — Mutual TLS helper functions
			 *
			 * certificateAuthorized, certificateSubjectMatches
			 */
			mTLS: {
				certificateAuthorized,
				certificateSubjectMatches
			},

			/*
			 * features.claimsParameter.assertClaimsParameter
			 */
			claimsParameter: {
				assertClaimsParameter
			},

			/*
			 * features.deviceFlow.* — Device Flow helper functions and HTML sources
			 *
			 * deviceInfo, userCodeInputSource, userCodeConfirmSource, successSource
			 */
			deviceFlow: {
				deviceInfo,
				userCodeInputSource,
				userCodeConfirmSource,
				successSource
			},

			/*
			 * features.introspection.allowedPolicy
			 */
			introspection: {
				allowedPolicy: introspectionAllowedPolicy
			},

			/*
			 * features.registration.* — Dynamic Client Registration helper functions
			 *
			 * idFactory, secretFactory
			 */
			registration: {
				idFactory,
				secretFactory
			},

			/*
			 * features.richAuthorizationRequests.* — RAR transform helper functions
			 *
			 * These must be provided by the deployment; the defaults throw via mustChange.
			 */
			richAuthorizationRequests: {
				rarForAuthorizationCode(_ctx) {
					// decision points:
					// - ctx.oidc.client
					// - ctx.oidc.resourceServers
					// - ctx.oidc.params.authorization_details (unparsed authorization_details from the authorization request)
					// - ctx.oidc.grant.rar (authorization_details granted)
					mustChange(
						'features.richAuthorizationRequests.rarForAuthorizationCode',
						'transform the requested and granted RAR details to be passed in the authorization code'
					);
					throw new Error(
						'features.richAuthorizationRequests.rarForAuthorizationCode not implemented'
					);
				},
				rarForCodeResponse(_ctx, _resourceServer) {
					mustChange(
						'features.richAuthorizationRequests.rarForCodeResponse',
						'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token'
					);
					throw new Error(
						'features.richAuthorizationRequests.rarForCodeResponse not implemented'
					);
				},
				rarForRefreshTokenResponse(_ctx, _resourceServer) {
					mustChange(
						'features.richAuthorizationRequests.rarForRefreshTokenResponse',
						'transform the requested and granted RAR details to be returned in the Access Token Response as authorization_details as well as assigned to the issued Access Token'
					);
					throw new Error(
						'features.richAuthorizationRequests.rarForRefreshTokenResponse not implemented'
					);
				},
				rarForIntrospectionResponse(_ctx, _token) {
					mustChange(
						'features.richAuthorizationRequests.rarForIntrospectionResponse',
						"transform the token's stored RAR details to be returned in the Introspection Response"
					);
					throw new Error(
						'features.richAuthorizationRequests.rarForIntrospectionResponse not implemented'
					);
				}
			},

			/*
			 * features.resourceIndicators.* — Resource Indicators helper functions
			 *
			 * defaultResource, useGrantedResource, getResourceServerInfo
			 */
			resourceIndicators: {
				defaultResource,
				useGrantedResource,
				getResourceServerInfo
			},

			/*
			 * features.requestObjects.assertJwtClaimsAndHeader
			 */
			requestObjects: {
				assertJwtClaimsAndHeader
			}
		},

		formats: {
			/*
			 * formats.customizers
			 *
			 * description: Customizer functions used before issuing a structured Access Token.
			 */
			customizers: {
				jwt: undefined
			}
		},

		/*
		 * expiresWithSession
		 *
		 * description: Function used to decide whether the given artifact should be bound to the user session.
		 */
		expiresWithSession,

		/*
		 * issueRefreshToken
		 *
		 * description: Function used to decide whether a refresh token will be issued or not
		 */
		issueRefreshToken,

		/*
		 * routes
		 *
		 * description: Routing values used by the authorization server. Only provide routes starting with "/"
		 */
		routes: {
			authorization: '/auth',
			backchannel_authentication: '/backchannel',
			code_verification: '/device',
			device_authorization: '/device/auth',
			end_session: '/session/end',
			introspection: '/token/introspection',
			jwks: '/jwks',
			pushed_authorization_request: '/request',
			registration: '/reg',
			revocation: '/token/revocation',
			token: '/token',
			userinfo: '/me'
		},

		/*
		 * pairwiseIdentifier
		 *
		 * description: Function used by the authorization server when resolving pairwise ID Token and Userinfo sub claim
		 *   values.
		 */
		pairwiseIdentifier,

		/*
		 * renderError
		 *
		 * description: Function used to present errors to the User-Agent
		 */
		renderError,

		/*
		 * sectorIdentifierUriValidate
		 *
		 * description: Function called to make a decision about whether sectorIdentifierUri of
		 * a client being loaded, registered, or updated should be fetched and its contents
		 * validated against the client metadata.
		 */
		sectorIdentifierUriValidate,

		/*
		 * interactions
		 *
		 * description: Holds the configuration for interaction policy and a URL to send end-users to
		 *   when the policy decides to require interaction.
		 *
		 * @nodefault
		 */
		interactions: {
			policy: defaultPolicy()
		},

		/*
		 * findAccount
		 *
		 * description: Function used to load an account and retrieve its available claims.
		 */
		findAccount,

		/*
		 * rotateRefreshToken
		 *
		 * description: Configures if and how the authorization server rotates refresh tokens after they are used.
		 */
		rotateRefreshToken
	};

	return defaults;
}

export default makeDefaults;
export const defaults = makeDefaults();
