import { Elysia, t } from 'elysia';
import certificateThumbprint from '../helpers/certificate_thumbprint.ts';
import instance from '../helpers/weak_cache.ts';
import filterClaims from '../helpers/filter_claims.ts';
import {
	dpopValidate,
	InvalidDpopProof,
	setNonceHeader,
	UseDpopNonce,
	validateReplay
} from '../helpers/validate_dpop.js';
import { InvalidToken, InsufficientScope } from '../helpers/errors.ts';
import { routeNames } from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Claims } from 'lib/helpers/claims.js';
import { IdToken } from 'lib/models/id_token.js';
import { Client } from 'lib/models/client.js';
import { provider } from 'lib/provider.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';
import { OAuthError, UserinfoResponse } from 'lib/shared/response_schemas.js';

async function userInfo({ headers, set }) {
	const oidc = new OIDCContext({}, headers);

	const accessTokenId = oidc.getAccessToken({
		acceptDPoP: true
	});
	let dPoP: Awaited<ReturnType<typeof dpopValidate>>;
	try {
		dPoP = await dpopValidate(headers.dpop, {
			accessTokenId,
			method: 'GET',
			route: routeNames.userinfo
		});
	} catch (err) {
		if (err instanceof UseDpopNonce || err instanceof InvalidDpopProof) {
			err.status = 401;
		}
		throw err;
	}
	setNonceHeader(set.headers, dPoP);

	const accessToken = await AccessToken.find(accessTokenId);
	if (!accessToken) {
		throw new InvalidToken('access token not found');
	}

	const { scopes } = accessToken;
	if (!scopes.size || !scopes.has('openid')) {
		throw new InsufficientScope('access token missing openid scope', 'openid');
	}

	if (accessToken.payload['x5t#S256']) {
		const cert = oidc.getClientCertificate();
		if (
			!cert ||
			accessToken.payload['x5t#S256'] !== certificateThumbprint(cert)
		) {
			throw new InvalidToken('failed x5t#S256 verification');
		}
	}

	await validateReplay(accessToken.payload.clientId, dPoP);

	if (
		accessToken.payload.jkt &&
		(!dPoP || accessToken.payload.jkt !== dPoP.thumbprint)
	) {
		throw new InvalidToken('failed jkt verification');
	}
	if (accessToken.payload.aud !== undefined) {
		throw new InvalidToken(
			'token audience prevents accessing the userinfo endpoint'
		);
	}

	const client = await Client.find(accessToken.payload.clientId);
	if (!client) {
		throw new InvalidToken('associated client not found');
	}

	const account = await instance(provider).configuration.findAccount(
		{ oidc },
		accessToken.payload.accountId,
		accessToken
	);

	if (!account) {
		throw new InvalidToken('associated account not found');
	}

	const grant = await Grant.find(accessToken.payload.grantId, {
		ignoreExpiration: true
	});

	if (!grant) {
		throw new InvalidToken('grant not found');
	}

	if (grant.isExpired) {
		throw new InvalidToken('grant is expired');
	}

	if (grant.payload.clientId !== accessToken.payload.clientId) {
		throw new InvalidToken('clientId mismatch');
	}

	if (grant.payload.accountId !== accessToken.payload.accountId) {
		throw new InvalidToken('accountId mismatch');
	}

	const claims = filterClaims(accessToken.payload.claims, 'userinfo', grant);
	const rejected = grant.getRejectedOIDCClaims();
	const scope = grant.getOIDCScopeFiltered(
		new Set(accessToken.payload.scope.split(' '))
	);

	if (client.userinfoSignedResponseAlg || client.userinfoEncryptedResponseAlg) {
		const token = new IdToken(
			client,
			await account.claims('userinfo', scope, claims, rejected)
		);

		token.scope = scope;
		token.mask = claims;
		token.rejected = rejected;

		const body = await token.issue({
			expiresAt: accessToken.payload.exp,
			use: 'userinfo'
		});
		return new Response(body, {
			headers: {
				'Content-Type': 'application/jwt; charset=utf-8'
			}
		});
	} else {
		const mask = new Claims(
			client,
			await account.claims('userinfo', scope, claims, rejected)
		);

		mask.scope(scope);
		mask.mask(claims);
		mask.rejected(rejected);

		return await mask.result();
	}
}

export const userinfo = new Elysia()
	.guard({
		schema: 'standalone',
		headers: t.Object({
			authorization: t.String({
				error: 'no access token provided'
			}),
			dpop: t.Optional(t.String())
		})
	})
	.get(routeNames.userinfo, userInfo, {
		response: { 200: UserinfoResponse, 401: OAuthError }
	})
	.post(routeNames.userinfo, userInfo, {
		response: { 200: UserinfoResponse, 401: OAuthError }
	});
