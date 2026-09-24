import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import combinedScope from './combined_scope.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { expiresWithSession, rarForAuthorizationCode } from '../addon/index.js';
import { includeSid } from '../models/client/checks.ts';

async function codeHandler(oidc: OIDCContext<PipelineParams>) {
	const grant = oidc.require('Grant');

	const scopeSet = combinedScope(
		grant,
		oidc.requestParamScopes,
		oidc.resourceServers
	);

	const code = new AuthorizationCode({
		/* The address this request was made to — there is no earlier artifact to inherit from. */
		bucketId: oidc.bucket._id,
		accountId: oidc.session.payload.accountId,
		acr: oidc.acr,
		amr: oidc.amr,
		authTime: oidc.session.authTime(),
		claims: oidc.claims,
		client: oidc.client,
		codeChallenge: oidc.params.code_challenge,
		codeChallengeMethod: oidc.params.code_challenge_method,
		grantId: oidc.session.grantIdFor(oidc.client.clientId),
		nonce: oidc.params.nonce,
		redirectUri: oidc.params.redirect_uri,
		resource: Object.keys(oidc.resourceServers),
		scope: [...scopeSet].join(' '),
		sessionUid: oidc.session.payload.uid,
		dpopJkt: oidc.params.dpop_jkt
	});

	/*
	 * Gated on the parameter, not on the flag alone. Running the shaping seam for every authorization
	 * request on a RAR-enabled deployment is what turned a flipped flag into a fault on requests that
	 * carried nothing for it to do. Empty is deleted rather than stored for the same reason `claims` is
	 * below: an empty array would surface as `"authorization_details": []` on responses to clients that
	 * never asked, and the introspection guard tests truthiness, where [] is truthy.
	 */
	if (
		ApplicationConfig['richAuthorizationRequests.enabled'] &&
		oidc.params.authorization_details
	) {
		code.payload.rar = await rarForAuthorizationCode(oidc);
		if (!code.payload.rar?.length) {
			delete code.payload.rar;
		}
	}

	if (Object.keys(code.payload.claims).length === 0) {
		delete code.payload.claims;
	}

	switch (code.payload.resource.length) {
		case 0:
			delete code.payload.resource;
			break;
		case 1:
			[code.payload.resource] = code.payload.resource;
			break;
	}

	if (await expiresWithSession(oidc, code)) {
		code.payload.expiresWithSession = true;
	} else {
		oidc.session.authorizationFor(oidc.client.clientId).persistsLogout = true;
	}

	if (
		includeSid(oidc.client) ||
		(oidc.claims.id_token && 'sid' in oidc.claims.id_token)
	) {
		code.payload.sid = oidc.session.sidFor(oidc.client.clientId);
	}

	oidc.entity('AuthorizationCode', code);

	return { code: await code.save() };
}

/* The authorization response members, before `state` and `iss` are added to them. */
export default async function processResponseTypes(
	oidc: OIDCContext<PipelineParams>
): Promise<Record<string, unknown>> {
	const responseType = oidc.params.response_type;

	if (responseType === 'code') {
		return codeHandler(oidc);
	}

	return {};
}
