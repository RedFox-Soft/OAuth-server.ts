import instance from './weak_cache.ts';
import combinedScope from './combined_scope.ts';

async function codeHandler(ctx) {
	const {
		expiresWithSession,
		features: { richAuthorizationRequests }
	} = instance(ctx.oidc.provider).configuration;

	const { grant } = ctx.oidc;

	const scopeSet = combinedScope(
		grant,
		ctx.oidc.requestParamScopes,
		ctx.oidc.resourceServers
	);

	const code = new ctx.oidc.provider.AuthorizationCode({
		accountId: ctx.oidc.session.accountId,
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
		sessionUid: ctx.oidc.session.uid,
		dpopJkt: ctx.oidc.params.dpop_jkt
	});

	if (richAuthorizationRequests.enabled) {
		code.rar = await richAuthorizationRequests.rarForAuthorizationCode(ctx);
	}

	if (Object.keys(code.claims).length === 0) {
		delete code.claims;
	}

	// eslint-disable-next-line default-case
	switch (code.resource.length) {
		case 0:
			delete code.resource;
			break;
		case 1:
			[code.resource] = code.resource;
			break;
	}

	if (await expiresWithSession(ctx, code)) {
		code.expiresWithSession = true;
	} else {
		ctx.oidc.session.authorizationFor(ctx.oidc.client.clientId).persistsLogout =
			true;
	}

	if (
		ctx.oidc.client.includeSid() ||
		(ctx.oidc.claims.id_token && 'sid' in ctx.oidc.claims.id_token)
	) {
		code.sid = ctx.oidc.session.sidFor(ctx.oidc.client.clientId);
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
