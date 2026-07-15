import difference from '../../helpers/_/difference.ts';
import {
	InvalidRequest,
	InvalidGrant,
	InvalidScope
} from '../../helpers/errors.ts';
import presence from '../../helpers/validate_presence.ts';
import instance from '../../helpers/weak_cache.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
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
import ResourceServer from 'lib/helpers/resource_server.js';

function rarSupported(token) {
	const [origin] = token.gty.split(' ');
	return origin !== cibaGty && origin !== deviceCodeGty;
}

const gty = 'refresh_token';

export const handler = async function refreshTokenHandler(oidc, dPoP) {
	presence(oidc, 'refresh_token');

	const {
		findAccount,
		conformIdTokenClaims,
		rotateRefreshToken,
		features: { userinfo, resourceIndicators, richAuthorizationRequests }
	} = instance(oidc.provider).configuration;

	const { client } = oidc;

	let refreshTokenValue = oidc.params.refresh_token;
	let refreshToken = await RefreshToken.find(refreshTokenValue, {
		ignoreExpiration: true,
		error: new InvalidGrant('refresh token not found')
	});

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
		cert = oidc.getClientCertificate();
		if (!cert) {
			throw new InvalidGrant('mutual TLS client certificate not provided');
		}
	}

	if (!dPoP && oidc.client.dpopBoundAccessTokens) {
		throw new InvalidGrant('DPoP proof JWT not provided');
	}

	if (
		refreshToken.payload['x5t#S256'] &&
		refreshToken.payload['x5t#S256'] !== certificateThumbprint(cert)
	) {
		throw new InvalidGrant('failed x5t#S256 verification');
	}

	const grant = await Grant.find(refreshToken.payload.grantId, {
		ignoreExpiration: true,
		error: new InvalidGrant('grant not found')
	});

	if (grant.isExpired) {
		throw new InvalidGrant('grant is expired');
	}

	if (grant.payload.clientId !== client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	if (oidc.params.scope) {
		const missing = difference(
			[...oidc.requestParamScopes],
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

	oidc.entity('RefreshToken', refreshToken);
	oidc.entity('Grant', grant);

	const account = await findAccount(
		{ oidc },
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

	oidc.entity('Account', account);

	if (refreshToken.payload.consumed) {
		await Promise.all([
			refreshToken.destroy(),
			revoke(oidc, refreshToken.payload.grantId)
		]);
		throw new InvalidGrant('refresh token already used');
	}

	if (oidc.params.authorization_details && !rarSupported(refreshToken)) {
		throw new InvalidRequest(
			'authorization_details is unsupported for this refresh token'
		);
	}

	if (
		rotateRefreshToken === true ||
		(typeof rotateRefreshToken === 'function' &&
			(await rotateRefreshToken({ oidc })))
	) {
		await refreshToken.consume();
		oidc.entity('RotatedRefreshToken', refreshToken);

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

		oidc.entity('RefreshToken', refreshToken);
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

	const scope = oidc.params.scope
		? oidc.requestParamScopes
		: refreshToken.scopes;
	await checkRar(oidc);
	const resource = await resolveResource(
		{ oidc },
		refreshToken,
		{ userinfo, resourceIndicators },
		scope
	);

	if (resource) {
		const resourceServerInfo = await resourceIndicators.getResourceServerInfo(
			{ oidc },
			resource,
			oidc.client
		);
		at.resourceServer = new ResourceServer(resource, resourceServerInfo);
		at.payload.scope = grant.getResourceScopeFiltered(
			resource,
			[...scope].filter(Set.prototype.has.bind(at.resourceServer.scopes))
		);
	} else {
		at.payload.claims = refreshToken.payload.claims;
		at.payload.scope = grant.getOIDCScopeFiltered(scope);
	}

	if (
		ApplicationConfig['richAuthorizationRequests.enabled'] &&
		at.resourceServer
	) {
		at.payload.rar = await richAuthorizationRequests.rarForRefreshTokenResponse(
			{ oidc },
			at.resourceServer
		);
	}

	oidc.entity('AccessToken', at);
	const accessToken = await at.save();

	let idToken;
	if (scope.has('openid')) {
		const claims = filterClaims(refreshToken.payload.claims, 'id_token', grant);
		const rejected = grant.getRejectedOIDCClaims();
		const token = new IdToken(oidc.client, {
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

		if (
			conformIdTokenClaims &&
			ApplicationConfig['userinfo.enabled'] &&
			!at.payload.aud
		) {
			token.scope = 'openid';
		} else {
			token.scope = grant.getOIDCScopeFiltered(scope);
		}
		token.mask = claims;
		token.rejected = rejected;

		token.set('nonce', refreshToken.payload.nonce);
		token.set('sid', refreshToken.payload.sid);

		idToken = await token.issue('idtoken');
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
