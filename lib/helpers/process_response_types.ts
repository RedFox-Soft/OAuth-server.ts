import combinedScope from './combined_scope.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { expiresWithSession, rarForAuthorizationCode } from '../addon/index.js';

async function codeHandler(ctx) {
	const { grant } = ctx.oidc;

	const scopeSet = combinedScope(
		grant,
		ctx.oidc.requestParamScopes,
		ctx.oidc.resourceServers
	);

	const code = new AuthorizationCode({
		accountId: ctx.oidc.session.payload.accountId,
		acr: ctx.oidc.acr,
		amr: ctx.oidc.amr,
		authTime: ctx.oidc.session.authTime(),
		claims: ctx.oidc.claims,
		client: ctx.oidc.client,
		codeChallenge: ctx.oidc.params.code_challenge,
		codeChallengeMethod: ctx.oidc.params.code_challenge_method,
		grantId: ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId),
		nonce: ctx.oidc.params.nonce,
		redirectUri: ctx.oidc.params.redirect_uri,
		resource: Object.keys(ctx.oidc.resourceServers),
		scope: [...scopeSet].join(' '),
		sessionUid: ctx.oidc.session.payload.uid,
		dpopJkt: ctx.oidc.params.dpop_jkt
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
		ctx.oidc.params.authorization_details
	) {
		code.payload.rar = await rarForAuthorizationCode(ctx);
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

	if (await expiresWithSession(ctx, code)) {
		code.payload.expiresWithSession = true;
	} else {
		ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout =
			true;
	}

	if (
		ctx.oidc.client.includeSid() ||
		(ctx.oidc.claims.id_token && 'sid' in ctx.oidc.claims.id_token)
	) {
		code.payload.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
	}

	ctx.oidc.entity('AuthorizationCode', code);

	return { code: await code.save() };
}

export default async function processResponseTypes(ctx) {
	const responseType = ctx.oidc.params.response_type;

	if (responseType === 'code') {
		return codeHandler(ctx);
	}

	return {};
}
