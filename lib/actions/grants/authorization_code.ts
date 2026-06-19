import { InvalidGrant } from '../../helpers/errors.ts';
import presence from '../../helpers/validate_presence.ts';
import instance from '../../helpers/weak_cache.ts';
import { verifyPKCE } from '../../helpers/pkce.js';
import revoke from '../../helpers/revoke.ts';
import filterClaims from '../../helpers/filter_claims.ts';
import resolveResource from '../../helpers/resolve_resource.ts';
import checkRar from '../../shared/check_rar.ts';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';

const gty = 'authorization_code';

export const handler = async function authorizationCodeHandler(oidc, dPoP) {
	const {
		findAccount,
		issueRefreshToken,
		allowOmittingSingleRegisteredRedirectUri,
		conformIdTokenClaims,
		features: { userinfo, resourceIndicators, richAuthorizationRequests }
	} = instance(oidc.provider).configuration;

	if (
		allowOmittingSingleRegisteredRedirectUri &&
		oidc.params.redirect_uri === undefined
	) {
		// It is permitted to omit the redirect_uri if only ONE is registered on the client
		const { 0: uri, length } = oidc.client.redirectUris;
		if (uri && length === 1) {
			oidc.params.redirect_uri = uri;
		}
	}

	presence(oidc, 'code', 'redirect_uri');

	const code = await AuthorizationCode.find(oidc.params.code, {
		ignoreExpiration: true
	});

	if (!code) {
		throw new InvalidGrant('authorization code not found');
	}
	if (code.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	if (code.isExpired) {
		throw new InvalidGrant('authorization code is expired');
	}

	if (!code.payload.grantId) {
		throw new InvalidGrant('authorization code malformed (grantId missing)');
	}

	const grant = await Grant.find(code.payload.grantId, {
		ignoreExpiration: true
	});

	if (!grant) {
		throw new InvalidGrant('grant not found');
	}

	if (grant.isExpired) {
		throw new InvalidGrant('grant is expired');
	}

	verifyPKCE(
		oidc.params.code_verifier,
		code.payload.codeChallenge,
		code.payload.codeChallengeMethod
	);

	let cert;
	if (oidc.client.tlsClientCertificateBoundAccessTokens) {
		cert = oidc.getClientCertificate();
		if (!cert) {
			throw new InvalidGrant('mutual TLS client certificate not provided');
		}
	}

	if (!dPoP && oidc.client.dpopBoundAccessTokens) {
		throw new InvalidGrant('DPoP proof JWT not provided');
	}

	if (grant.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	if (code.payload.redirectUri !== oidc.params.redirect_uri) {
		throw new InvalidGrant('authorization code redirect_uri mismatch');
	}

	if (code.payload.consumed) {
		await revoke({ oidc }, code.payload.grantId);
		throw new InvalidGrant('authorization code already consumed');
	}

	await code.consume();

	oidc.entity('AuthorizationCode', code);
	oidc.entity('Grant', grant);

	const account = await findAccount({ oidc }, code.payload.accountId, code);

	if (!account) {
		throw new InvalidGrant(
			'authorization code invalid (referenced account not found)'
		);
	}

	if (code.payload.accountId !== grant.payload.accountId) {
		throw new InvalidGrant('accountId mismatch');
	}

	oidc.entity('Account', account);

	const at = new AccessToken({
		accountId: account.accountId,
		client: oidc.client,
		expiresWithSession: code.payload.expiresWithSession,
		grantId: code.payload.grantId,
		gty,
		sessionUid: code.payload.sessionUid,
		sid: code.payload.sid
	});

	if (oidc.client.tlsClientCertificateBoundAccessTokens) {
		at.setThumbprint('x5t', cert);
	}

	if (code.payload.dpopJkt && !dPoP) {
		throw new InvalidGrant('missing DPoP proof JWT');
	}

	if (dPoP) {
		if (code.payload.dpopJkt && code.payload.dpopJkt !== dPoP.thumbprint) {
			throw new InvalidGrant(
				'DPoP proof key thumbprint does not match dpop_jkt'
			);
		}

		at.setThumbprint('jkt', dPoP.thumbprint);
	}

	await checkRar(oidc);
	const resource = await resolveResource({ oidc }, code, {
		userinfo,
		resourceIndicators
	});

	if (resource) {
		const resourceServerInfo = await resourceIndicators.getResourceServerInfo(
			{ oidc },
			resource,
			oidc.client
		);
		at.resourceServer = new oidc.provider.ResourceServer(
			resource,
			resourceServerInfo
		);
		at.payload.scope = grant.getResourceScopeFiltered(resource, code.scopes);
	} else {
		at.payload.claims = code.payload.claims;
		at.payload.scope = grant.getOIDCScopeFiltered(code.scopes);
	}

	if (richAuthorizationRequests.enabled && at.resourceServer) {
		at.payload.rar = await richAuthorizationRequests.rarForCodeResponse(
			{ oidc },
			at.resourceServer
		);
	}

	oidc.entity('AccessToken', at);
	const accessToken = await at.save();

	let refreshToken;
	if (await issueRefreshToken({ oidc }, oidc.client, code)) {
		const rt = new RefreshToken({
			accountId: account.accountId,
			acr: code.payload.acr,
			amr: code.payload.amr,
			authTime: code.payload.authTime,
			claims: code.payload.claims,
			client: oidc.client,
			expiresWithSession: code.payload.expiresWithSession,
			grantId: code.payload.grantId,
			gty,
			nonce: code.payload.nonce,
			resource: code.payload.resource,
			rotations: 0,
			scope: code.payload.scope,
			sessionUid: code.payload.sessionUid,
			sid: code.payload.sid,
			rar: code.payload.rar
		});

		if (oidc.client.clientAuthMethod === 'none') {
			if (at.payload.jkt) {
				rt.payload.jkt = at.payload.jkt;
			}

			if (at.payload['x5t#S256']) {
				rt.payload['x5t#S256'] = at.payload['x5t#S256'];
			}
		}

		oidc.entity('RefreshToken', rt);
		refreshToken = await rt.save();
	}

	let idToken;
	if (code.scopes.has('openid')) {
		const claims = filterClaims(code.payload.claims, 'id_token', grant);
		const rejected = grant.getRejectedOIDCClaims();
		const token = new IdToken(oidc.client, {
			...(await account.claims(
				'id_token',
				code.payload.scope,
				claims,
				rejected
			)),
			acr: code.payload.acr,
			amr: code.payload.amr,
			auth_time: code.payload.authTime
		});

		if (conformIdTokenClaims && userinfo.enabled && !at.aud) {
			token.scope = 'openid';
		} else {
			token.scope = grant.getOIDCScopeFiltered(code.scopes);
		}

		token.mask = claims;
		token.rejected = rejected;

		token.set('nonce', code.payload.nonce);
		token.set('sid', code.payload.sid);

		idToken = await token.issue({ use: 'idtoken' });
	}

	return {
		access_token: accessToken,
		expires_in: at.expiration,
		id_token: idToken,
		refresh_token: refreshToken,
		scope: code.payload.scope || at.payload.scope || undefined,
		token_type: at.tokenType,
		authorization_details: at.payload.rar
	};
};
