import difference from '../../helpers/_/difference.ts';
import {
	InvalidRequest,
	InvalidGrant,
	InvalidScope
} from '../../helpers/errors.ts';
import presence from '../../helpers/validate_presence.ts';
import instance from '../../helpers/weak_cache.ts';
import revoke from '../../helpers/revoke.ts';
import certificateThumbprint from '../../helpers/certificate_thumbprint.ts';
import * as formatters from '../../helpers/formatters.ts';
import filterClaims from '../../helpers/filter_claims.ts';
import resolveResource from '../../helpers/resolve_resource.ts';
import checkRar from '../../shared/check_rar.ts';

import { gty as cibaGty } from './ciba.ts';
import { gty as deviceCodeGty } from './device_code.ts';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';

function rarSupported(token) {
	const [origin] = token.gty.split(' ');
	return origin !== cibaGty && origin !== deviceCodeGty;
}

const gty = 'refresh_token';

export const handler = async function refreshTokenHandler(ctx, dPoP) {
	presence(ctx, 'refresh_token');

	const {
		findAccount,
		conformIdTokenClaims,
		rotateRefreshToken,
		features: {
			userinfo,
			mTLS: { getCertificate },
			resourceIndicators,
			richAuthorizationRequests
		}
	} = instance(ctx.oidc.provider).configuration;

	const { client } = ctx.oidc;

	let refreshTokenValue = ctx.oidc.params.refresh_token;
	let refreshToken = await RefreshToken.find(refreshTokenValue, {
		ignoreExpiration: true
	});

	if (!refreshToken) {
		throw new InvalidGrant('refresh token not found');
	}

	if (refreshToken.payload.clientId !== client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	if (refreshToken.isExpired) {
		throw new InvalidGrant('refresh token is expired');
	}

	let cert;
	if (
		client.tlsClientCertificateBoundAccessTokens ||
		refreshToken.payload['x5t#S256']
	) {
		cert = getCertificate(ctx);
		if (!cert) {
			throw new InvalidGrant('mutual TLS client certificate not provided');
		}
	}

	if (!dPoP && ctx.oidc.client.dpopBoundAccessTokens) {
		throw new InvalidGrant('DPoP proof JWT not provided');
	}

	if (
		refreshToken.payload['x5t#S256'] &&
		refreshToken.payload['x5t#S256'] !== certificateThumbprint(cert)
	) {
		throw new InvalidGrant('failed x5t#S256 verification');
	}

	const grant = await Grant.find(refreshToken.payload.grantId, {
		ignoreExpiration: true
	});

	if (!grant) {
		throw new InvalidGrant('grant not found');
	}

	if (grant.isExpired) {
		throw new InvalidGrant('grant is expired');
	}

	if (grant.payload.clientId !== client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	if (ctx.oidc.params.scope) {
		const missing = difference(
			[...ctx.oidc.requestParamScopes],
			[...refreshToken.scopes]
		);

		if (missing.length !== 0) {
			throw new InvalidScope(
				`refresh token missing requested ${formatters.pluralize('scope', missing.length)}`,
				missing.join(' ')
			);
		}
	}

	if (
		refreshToken.payload.jkt &&
		(!dPoP || refreshToken.payload.jkt !== dPoP.thumbprint)
	) {
		throw new InvalidGrant('failed jkt verification');
	}

	ctx.oidc.entity('RefreshToken', refreshToken);
	ctx.oidc.entity('Grant', grant);

	const account = await findAccount(
		ctx,
		refreshToken.payload.accountId,
		refreshToken
	);

	if (!account) {
		throw new InvalidGrant(
			'refresh token invalid (referenced account not found)'
		);
	}

	if (refreshToken.payload.accountId !== grant.payload.accountId) {
		throw new InvalidGrant('accountId mismatch');
	}

	ctx.oidc.entity('Account', account);

	if (refreshToken.payload.consumed) {
		await Promise.all([
			refreshToken.destroy(),
			revoke(ctx, refreshToken.payload.grantId)
		]);
		throw new InvalidGrant('refresh token already used');
	}

	if (ctx.oidc.params.authorization_details && !rarSupported(refreshToken)) {
		throw new InvalidRequest(
			'authorization_details is unsupported for this refresh token'
		);
	}

	if (
		rotateRefreshToken === true ||
		(typeof rotateRefreshToken === 'function' &&
			(await rotateRefreshToken(ctx)))
	) {
		await refreshToken.consume();
		ctx.oidc.entity('RotatedRefreshToken', refreshToken);

		refreshToken = new RefreshToken({
			accountId: refreshToken.payload.accountId,
			acr: refreshToken.payload.acr,
			amr: refreshToken.payload.amr,
			authTime: refreshToken.payload.authTime,
			claims: refreshToken.payload.claims,
			client,
			expiresWithSession: refreshToken.payload.expiresWithSession,
			iiat: refreshToken.payload.iiat,
			grantId: refreshToken.payload.grantId,
			gty: refreshToken.payload.gty,
			nonce: refreshToken.payload.nonce,
			resource: refreshToken.payload.resource,
			rotations:
				typeof refreshToken.payload.rotations === 'number'
					? refreshToken.payload.rotations + 1
					: 1,
			scope: refreshToken.payload.scope,
			sessionUid: refreshToken.payload.sessionUid,
			sid: refreshToken.payload.sid,
			rar: refreshToken.payload.rar,
			'x5t#S256': refreshToken.payload['x5t#S256'],
			jkt: refreshToken.payload.jkt
		});

		if (refreshToken.payload.gty && !refreshToken.payload.gty.endsWith(gty)) {
			refreshToken.payload.gty = `${refreshToken.payload.gty} ${gty}`;
		}

		ctx.oidc.entity('RefreshToken', refreshToken);
		refreshTokenValue = await refreshToken.save();
	}

	const at = new AccessToken({
		accountId: account.accountId,
		client,
		expiresWithSession: refreshToken.payload.expiresWithSession,
		grantId: refreshToken.payload.grantId,
		gty: refreshToken.payload.gty,
		sessionUid: refreshToken.payload.sessionUid,
		sid: refreshToken.payload.sid
	});

	if (client.tlsClientCertificateBoundAccessTokens) {
		at.setThumbprint('x5t', cert);
	}

	if (dPoP) {
		at.setThumbprint('jkt', dPoP.thumbprint);
	}

	if (at.payload.gty && !at.payload.gty.endsWith(gty)) {
		at.payload.gty = `${at.payload.gty} ${gty}`;
	}

	const scope = ctx.oidc.params.scope
		? ctx.oidc.requestParamScopes
		: refreshToken.scopes;
	await checkRar(ctx);
	const resource = await resolveResource(
		ctx,
		refreshToken,
		{ userinfo, resourceIndicators },
		scope
	);

	if (resource) {
		const resourceServerInfo = await resourceIndicators.getResourceServerInfo(
			ctx,
			resource,
			ctx.oidc.client
		);
		at.resourceServer = new ctx.oidc.provider.ResourceServer(
			resource,
			resourceServerInfo
		);
		at.payload.scope = grant.getResourceScopeFiltered(
			resource,
			[...scope].filter(Set.prototype.has.bind(at.resourceServer.scopes))
		);
	} else {
		at.payload.claims = refreshToken.payload.claims;
		at.payload.scope = grant.getOIDCScopeFiltered(scope);
	}

	if (richAuthorizationRequests.enabled && at.resourceServer) {
		at.payload.rar = await richAuthorizationRequests.rarForRefreshTokenResponse(
			ctx,
			at.resourceServer
		);
	}

	ctx.oidc.entity('AccessToken', at);
	const accessToken = await at.save();

	let idToken;
	if (scope.has('openid')) {
		const claims = filterClaims(refreshToken.payload.claims, 'id_token', grant);
		const rejected = grant.getRejectedOIDCClaims();
		const token = new IdToken(ctx.oidc.client, {
			...(await account.claims(
				'id_token',
				[...scope].join(' '),
				claims,
				rejected
			)),
			acr: refreshToken.payload.acr,
			amr: refreshToken.payload.amr,
			auth_time: refreshToken.payload.authTime
		});

		if (conformIdTokenClaims && userinfo.enabled && !at.payload.aud) {
			token.scope = 'openid';
		} else {
			token.scope = grant.getOIDCScopeFiltered(scope);
		}
		token.mask = claims;
		token.rejected = rejected;

		token.set('nonce', refreshToken.payload.nonce);
		token.set('sid', refreshToken.payload.sid);

		idToken = await token.issue({ use: 'idtoken' });
	}

	return {
		access_token: accessToken,
		expires_in: at.expiration,
		id_token: idToken,
		refresh_token: refreshTokenValue,
		scope: at.payload.scope || undefined,
		token_type: at.tokenType,
		authorization_details: at.payload.rar
	};
};
