import bodyParser from '../../shared/conditional_body.ts';
import rejectDupes from '../../shared/reject_dupes.ts';
import paramsMiddleware from '../../shared/assemble_params.ts';
import sessionMiddleware from '../../shared/session.ts';
import instance from '../../helpers/weak_cache.ts';
import { PARAM_LIST } from '../../consts/index.ts';
import checkRar from '../../shared/check_rar.ts';
import checkResource from '../../shared/check_resource.ts';
import getTokenAuth from '../../shared/token_auth.ts';

import checkClient from './check_client.ts';
import checkResponseMode from './check_response_mode.ts';
import rejectUnsupported from './reject_unsupported.ts';
import rejectRegistration from './reject_registration.ts';
import oneRedirectUriClients from './one_redirect_uri_clients.ts';
import processRequestObject from './process_request_object.ts';
import oidcRequired from './oidc_required.ts';
import cibaRequired from './ciba_required.ts';
import checkPrompt from './check_prompt.ts';
import checkMaxAge from './check_max_age.ts';
import checkIdTokenHint from './check_id_token_hint.ts';
import checkScope from './check_scope.ts';
import checkResponseType from './check_response_type.ts';
import checkRedirectUri from './check_redirect_uri.ts';
import assignDefaults from './assign_defaults.ts';
import checkClaims from './check_claims.ts';
import assignClaims from './assign_claims.ts';
import loadAccount from './load_account.ts';
import loadGrant from './load_grant.ts';
import interactions from './interactions.ts';
import interactionEmit from './interaction_emit.ts';
import getResume from './resume.ts';
import checkClientGrantType from './check_client_grant_type.ts';
import checkOpenidScope from './check_openid_scope.ts';
import deviceAuthorizationResponse from './device_authorization_response.ts';
import authenticatedClientId from './authenticated_client_id.ts';
import deviceUserFlow from './device_user_flow.ts';
import deviceUserFlowErrors from './device_user_flow_errors.ts';
import deviceUserFlowResponse from './device_user_flow_response.ts';
import pushedAuthorizationRequestRemapErrors from './pushed_authorization_request_remap_errors.ts';
import backchannelRequestRemapErrors from './backchannel_request_remap_errors.ts';
import stripOutsideJarParams from './strip_outside_jar_params.ts';
import pushedAuthorizationRequestResponse from './pushed_authorization_request_response.ts';
import cibaLoadAccount from './ciba_load_account.ts';
import checkRequestedExpiry from './check_requested_expiry.ts';
import backchannelRequestResponse from './backchannel_request_response.ts';
import checkCibaContext from './check_ciba_context.ts';
import checkDpopJkt from './check_dpop_jkt.ts';
import unsupportedRar from './unsupported_rar.ts';

const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';
const PAR = 'pushed_authorization_request';
const BA = 'backchannel_authentication';

const authRequired = new Set([DA, PAR, BA]);

const parseBody = bodyParser.bind(
	undefined,
	'application/x-www-form-urlencoded'
);

import { authorizationPKCE } from '../../helpers/pkce.ts';
function checkPKCE({ oidc: { params } }, next) {
	authorizationPKCE(params);
	return next();
}

export default function authorizationAction(provider, endpoint) {
	const {
		features: {
			claimsParameter,
			dPoP,
			resourceIndicators,
			richAuthorizationRequests,
			webMessageResponseMode
		}
	} = instance(provider).configuration;

	const allowList = new Set(PARAM_LIST);

	if (webMessageResponseMode.enabled) {
		allowList.add('web_message_uri'); // adding it just so that it can be rejected when detected
	}

	if (claimsParameter.enabled) {
		allowList.add('claims');
	}

	let rejectDupesMiddleware = rejectDupes.bind(undefined, {});
	if (resourceIndicators.enabled) {
		allowList.add('resource');
		rejectDupesMiddleware = rejectDupes.bind(undefined, {
			except: new Set(['resource'])
		});
	}

	if (richAuthorizationRequests.enabled) {
		allowList.add('authorization_details');
	}

	if ([DA, CV, DR, BA].includes(endpoint)) {
		allowList.delete('web_message_uri');
		allowList.delete('response_type');
		allowList.delete('response_mode');
		allowList.delete('code_challenge_method');
		allowList.delete('code_challenge');
		allowList.delete('state');
		allowList.delete('redirect_uri');
		allowList.delete('prompt');
	}

	if (endpoint === BA) {
		allowList.add('client_notification_token');
		allowList.add('login_hint_token');
		allowList.add('binding_message');
		allowList.add('user_code');
		allowList.add('request_context');
		allowList.add('requested_expiry');
	}

	if (dPoP && [A, R, PAR].includes(endpoint)) {
		allowList.add('dpop_jkt');
	}

	const stack = [];

	const use = (middleware, ...only) => {
		if (only.includes(endpoint)) {
			stack.push(middleware);
		}
	};

	const returnTo = /^(code|device)_/.test(endpoint)
		? 'device_resume'
		: 'resume';

	use(sessionMiddleware, DR);
	use(deviceUserFlowErrors, CV, DR);
	use(getResume.bind(undefined, allowList, returnTo), DR);
	use(deviceUserFlow.bind(undefined, allowList), CV, DR);
	use(parseBody, DA, PAR, BA);
	if (authRequired.has(endpoint)) {
		const { params: authParams, middleware: tokenAuth } =
			getTokenAuth(provider);
		use(paramsMiddleware.bind(undefined, authParams), DA, PAR, BA);
		tokenAuth.forEach((tokenAuthMiddleware) => {
			use(tokenAuthMiddleware, DA, PAR, BA);
		});
	}
	use(authenticatedClientId, DA, BA);
	use(paramsMiddleware.bind(undefined, allowList), DA, PAR, BA);
	use(rejectDupesMiddleware, DA, PAR, BA);
	use(rejectUnsupported, DA, PAR, BA);
	use(stripOutsideJarParams, PAR, BA);
	use(checkClient, DA, CV, DR);
	use(checkClientGrantType, DA, BA);
	use(pushedAuthorizationRequestRemapErrors, PAR);
	use(backchannelRequestRemapErrors, BA);
	use(
		processRequestObject.bind(undefined, allowList, rejectDupesMiddleware),
		DA,
		PAR,
		BA
	);
	use(checkResponseMode, PAR);
	use(oneRedirectUriClients, PAR);
	use(rejectRegistration, DA, PAR, BA);
	use(checkResponseType, PAR);
	use(oidcRequired, PAR);
	use(cibaRequired, BA);
	use(assignDefaults, DA, BA);
	use(checkPrompt, PAR);
	use(checkScope.bind(undefined, allowList), DA, PAR, BA);
	use(checkOpenidScope, DA, PAR, BA);
	use(checkRedirectUri, PAR);
	use(checkPKCE, PAR);
	use(checkClaims, DA, PAR, BA);
	use(unsupportedRar, DA, BA);
	use(checkRar, PAR);
	use(checkResource, DA, CV, DR, PAR, BA);
	use(checkMaxAge, DA, PAR, BA);
	use(checkRequestedExpiry, BA);
	use(checkCibaContext, BA);
	use(checkIdTokenHint, DA, PAR);
	use(checkDpopJkt, PAR);
	use(interactionEmit, CV, DR);
	use(assignClaims, CV, DR, BA);
	use(cibaLoadAccount, BA);
	use(loadAccount, CV, DR);
	use(loadGrant, CV, DR);
	use(interactions.bind(undefined, returnTo), CV, DR);
	use(deviceAuthorizationResponse, DA);
	use(deviceUserFlowResponse, CV, DR);
	use(pushedAuthorizationRequestResponse, PAR);
	use(backchannelRequestResponse, BA);

	return stack;
}
