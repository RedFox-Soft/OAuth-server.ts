import instance from './weak_cache.ts';
import filterClaims from './filter_claims.ts';
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

async function idTokenHandler(ctx) {
	const claims = filterClaims(ctx.oidc.claims, 'id_token', ctx.oidc.grant);
	const rejected = ctx.oidc.grant.getRejectedOIDCClaims();
	const scope = ctx.oidc.grant.getOIDCScopeFiltered(
		ctx.oidc.requestParamScopes
	);
	const idToken = new ctx.oidc.provider.IdToken(
		{
			...(await ctx.oidc.account.claims('id_token', scope, claims, rejected)),
			acr: ctx.oidc.acr,
			amr: ctx.oidc.amr,
			auth_time: ctx.oidc.session.authTime()
		},
		{ ctx }
	);

	const {
		conformIdTokenClaims,
		features: { userinfo }
	} = instance(ctx.oidc.provider).configuration;

	if (
		conformIdTokenClaims &&
		userinfo.enabled &&
		ctx.oidc.params.response_type !== 'id_token' &&
		!ctx.oidc.params.resource
	) {
		idToken.scope = 'openid';
	} else {
		idToken.scope = scope;
	}

	idToken.mask = claims;
	idToken.rejected = rejected;

	idToken.set('nonce', ctx.oidc.params.nonce);

	if (
		ctx.oidc.client.includeSid() ||
		(ctx.oidc.claims.id_token && 'sid' in ctx.oidc.claims.id_token)
	) {
		idToken.set('sid', ctx.oidc.session.sidFor(ctx.oidc.client.clientId));
	}

	return { id_token: idToken };
}

/*
 * Resolves each requested response type to a single response object. If one of the hybrid
 * response types is used an appropriate _hash is also pushed on to the id_token.
 */
export default async function processResponseTypes(ctx) {
	const responses = ctx.oidc.params.response_type.split(' ');
	const response = Object.assign(
		{},
		...(await Promise.all(
			responses.map((responseType) => {
				switch (responseType) {
					case 'code':
						return codeHandler(ctx);
					case 'id_token':
						return idTokenHandler(ctx);
					default:
						return {};
				}
			})
		))
	);

	if ('id_token' in response) {
		response.id_token = await response.id_token.issue({ use: 'idtoken' });
	}

	return response;
}
