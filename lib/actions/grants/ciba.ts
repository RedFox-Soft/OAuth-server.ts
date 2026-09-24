import type { X509Certificate } from 'node:crypto';
import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { TokenParams } from 'lib/actions/token.js';
import * as errors from '../../helpers/errors.ts';
import presence from '../../helpers/validate_presence.ts';
import { findAccount } from '../../addon/account.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import filterClaims from '../../helpers/filter_claims.ts';
import revoke from '../../helpers/revoke.ts';
import resolveResource from '../../helpers/resolve_resource.ts';
import { getResourceServerInfo, issueRefreshToken } from '../../addon/index.js';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.js';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { Grant } from 'lib/models/grant.js';
import ResourceServer from 'lib/helpers/resource_server.js';
import type { DPoPProof } from 'lib/helpers/validate_dpop.js';

const { AuthorizationPending, ExpiredToken, InvalidGrant } = errors;

export const gty = 'ciba';

export const handler = async function cibaHandler(
	oidc: OIDCContext<TokenParams>,
	dPoP: DPoPProof
) {
	presence(oidc, 'auth_req_id');

	if (oidc.params.authorization_details) {
		throw new errors.InvalidRequest(
			'authorization_details is unsupported for this grant_type'
		);
	}

	const request = await BackchannelAuthenticationRequest.find(
		oidc.params.auth_req_id,
		{
			ignoreExpiration: true,
			error: new InvalidGrant('backchannel authentication request not found')
		}
	);

	if (request.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	let cert: X509Certificate | undefined;
	if (oidc.client.tlsClientCertificateBoundAccessTokens) {
		cert = oidc.getClientCertificate();
		if (!cert) {
			throw new InvalidGrant('mutual TLS client certificate not provided');
		}
	}

	if (!dPoP && oidc.client.dpopBoundAccessTokens) {
		throw new InvalidGrant('DPoP proof JWT not provided');
	}

	if (request.isExpired) {
		throw new ExpiredToken('backchannel authentication request is expired');
	}

	if (!request.payload.grantId && !request.payload.error) {
		throw new AuthorizationPending();
	}

	if (request.payload.consumed) {
		if (request.payload.grantId) await revoke(request.payload.grantId, oidc);
		throw new InvalidGrant(
			'backchannel authentication request already consumed'
		);
	}

	await request.consume();

	if (request.payload.error) {
		throw errors.errorForCode(
			request.payload.error,
			request.payload.errorDescription
		);
	}

	const { grantId } = request.payload;
	if (!grantId) {
		throw new InvalidGrant('grant not found');
	}
	const grant = await Grant.find(grantId, {
		ignoreExpiration: true,
		error: new InvalidGrant('grant not found')
	});

	if (grant.isExpired) {
		throw new InvalidGrant('grant is expired');
	}

	if (grant.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	oidc.entity('BackchannelAuthenticationRequest', request);
	oidc.entity('Grant', grant);

	const account = await findAccount(oidc, request.payload.accountId, request);

	if (!account) {
		throw new InvalidGrant(
			'backchannel authentication request invalid (referenced account not found)'
		);
	}

	if (request.payload.accountId !== grant.payload.accountId) {
		throw new InvalidGrant('accountId mismatch');
	}

	oidc.entity('Account', account);

	const at = new AccessToken({
		/* Inherited from the artifact being redeemed, not from the address this redemption arrived at:
		 * the issuer is a fact about where the grant was established. */
		bucketId: request.payload.bucketId,
		accountId: account.accountId,
		client: oidc.client,
		expiresWithSession: request.payload.expiresWithSession,
		grantId: request.payload.grantId,
		gty,
		sessionUid: request.payload.sessionUid,
		sid: request.payload.sid
	});

	if (oidc.client.tlsClientCertificateBoundAccessTokens && cert) {
		at.setThumbprint('x5t', cert);
	}

	if (dPoP) {
		at.setThumbprint('jkt', dPoP.thumbprint);
	}

	const resource = await resolveResource(oidc, request);

	if (resource) {
		const resourceServerInfo = await getResourceServerInfo(
			oidc,
			resource,
			oidc.client
		);
		at.resourceServer = new ResourceServer(resource, resourceServerInfo);
		at.payload.scope = grant.getResourceScopeFiltered(resource, request.scopes);
	} else {
		at.payload.claims = request.payload.claims;
		at.payload.scope = grant.getOIDCScopeFiltered(request.scopes);
	}

	oidc.entity('AccessToken', at);
	const accessToken = await at.save();

	let refreshToken;
	if (await issueRefreshToken(oidc, oidc.client, request)) {
		const rt = new RefreshToken({
			bucketId: request.payload.bucketId,
			accountId: account.accountId,
			acr: request.payload.acr,
			amr: request.payload.amr,
			authTime: request.payload.authTime,
			claims: request.payload.claims,
			client: oidc.client,
			expiresWithSession: request.payload.expiresWithSession,
			grantId: request.payload.grantId,
			gty,
			nonce: request.payload.nonce,
			resource: request.payload.resource,
			rotations: 0,
			scope: request.payload.scope,
			sessionUid: request.payload.sessionUid,
			sid: request.payload.sid
		});

		if (oidc.client.tokenEndpointAuthMethod === 'none') {
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
	if (request.scopes.has('openid')) {
		const claims = filterClaims(request.payload.claims, 'id_token', grant);
		const rejected = grant.getRejectedOIDCClaims();
		const token = new IdToken(
			oidc.client,
			{
				...(await account.claims(
					'id_token',
					request.payload.scope,
					claims,
					rejected
				)),
				...{
					acr: request.payload.acr,
					amr: request.payload.amr,
					auth_time: request.payload.authTime
				}
			},
			/* The bucket the grant was established in — a relying party compares this token's `iss`
			 * against the metadata it discovered for that bucket, not for whichever address this
			 * redemption arrived at. */
			await issuingBucket(request.payload.bucketId)
		);

		if (
			ApplicationConfig.conformIdTokenClaims &&
			ApplicationConfig['userinfo.enabled'] &&
			!at.payload.aud
		) {
			token.scope = 'openid';
		} else {
			token.scope = grant.getOIDCScopeFiltered(request.scopes);
		}

		token.mask = claims;
		token.rejected = rejected;

		token.set('nonce', request.payload.nonce);
		token.set('sid', request.payload.sid);

		idToken = await token.issue('idtoken');
	}

	return {
		access_token: accessToken,
		expires_in: at.expiration,
		id_token: idToken,
		refresh_token: refreshToken,
		scope: at.payload.scope || undefined,
		token_type: at.tokenType
	};
};
