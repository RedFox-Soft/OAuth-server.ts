import bodyParser from '../../shared/conditional_body.ts';
import rejectDupes from '../../shared/reject_dupes.ts';
import paramsMiddleware from '../../shared/assemble_params.ts';
import sessionMiddleware from '../../shared/session.ts';
import instance from '../../helpers/weak_cache.ts';
import { PARAM_LIST } from '../../consts/index.ts';
import checkResource from '../../shared/check_resource.ts';
import getTokenAuth from '../../shared/token_auth.ts';

import checkClient from './check_client.ts';
import processRequestObject from './process_request_object.ts';
import cibaRequired from './ciba_required.ts';
import checkMaxAge from './check_max_age.ts';
import checkIdTokenHint from './check_id_token_hint.ts';
import checkScope from './check_scope.ts';
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
import backchannelRequestRemapErrors from './backchannel_request_remap_errors.ts';
import stripOutsideJarParams from './strip_outside_jar_params.ts';
import cibaLoadAccount from './ciba_load_account.ts';
import checkRequestedExpiry from './check_requested_expiry.ts';
import backchannelRequestResponse from './backchannel_request_response.ts';
import checkCibaContext from './check_ciba_context.ts';
import unsupportedRar from './unsupported_rar.ts';

const DA = 'device_authorization';
const CV = 'code_verification';
const DR = 'device_resume';
const BA = 'backchannel_authentication';

const authRequired = new Set([DA, BA]);

const parseBody = bodyParser.bind(
	undefined,
	'application/x-www-form-urlencoded'
);

export default function authorizationAction(provider, endpoint) {
	const {
		features: {
			claimsParameter,
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
	use(parseBody, DA, BA);
	if (authRequired.has(endpoint)) {
		const { params: authParams, middleware: tokenAuth } =
			getTokenAuth(provider);
		use(paramsMiddleware.bind(undefined, authParams), DA, BA);
		tokenAuth.forEach((tokenAuthMiddleware) => {
			use(tokenAuthMiddleware, DA, BA);
		});
	}
	use(authenticatedClientId, DA, BA);
	use(paramsMiddleware.bind(undefined, allowList), DA, BA);
	use(rejectDupesMiddleware, DA, BA);
	// use(rejectUnsupported, DA, BA);
	use(stripOutsideJarParams, BA);
	use(checkClient, DA, CV, DR);
	use(checkClientGrantType, DA, BA);
	use(backchannelRequestRemapErrors, BA);
	use(
		processRequestObject.bind(undefined, allowList, rejectDupesMiddleware),
		DA,
		BA
	);
	// use(rejectRegistration, DA, BA);
	use(cibaRequired, BA);
	use(assignDefaults, DA, BA);
	use(checkScope.bind(undefined, allowList), DA, BA);
	use(checkOpenidScope, DA, BA);
	use(checkClaims, DA, BA);
	use(unsupportedRar, DA, BA);
	use(checkResource, DA, CV, DR, BA);
	use(checkMaxAge, DA, BA);
	use(checkRequestedExpiry, BA);
	use(checkCibaContext, BA);
	use(checkIdTokenHint, DA);
	use(interactionEmit, CV, DR);
	use(assignClaims, CV, DR, BA);
	use(cibaLoadAccount, BA);
	use(loadAccount, CV, DR);
	use(loadGrant, CV, DR);
	use(interactions.bind(undefined, returnTo), CV, DR);
	use(deviceAuthorizationResponse, DA);
	use(deviceUserFlowResponse, CV, DR);
	use(backchannelRequestResponse, BA);

	return stack;
}
