import upperFirst from '../../helpers/_/upper_first.ts';
import camelCase from '../../helpers/_/camel_case.ts';
import * as errors from '../../helpers/errors.ts';
import presence from '../../helpers/validate_presence.ts';
import instance from '../../helpers/weak_cache.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import filterClaims from '../../helpers/filter_claims.ts';
import revoke from '../../helpers/revoke.ts';
import resolveResource from '../../helpers/resolve_resource.ts';
import { IdToken } from 'lib/models/id_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';

const { AuthorizationPending, ExpiredToken, InvalidGrant } = errors;

export const gty = 'ciba';

export const handler = async function cibaHandler(oidc, dPoP) {
	presence(oidc, 'auth_req_id');

	if (oidc.params.authorization_details) {
		throw new errors.InvalidRequest(
			'authorization_details is unsupported for this grant_type'
		);
	}

	const {
		findAccount,
		issueRefreshToken,
		conformIdTokenClaims,
		features: { userinfo, resourceIndicators }
	} = instance(oidc.provider).configuration;

	const request = await oidc.provider.BackchannelAuthenticationRequest.find(
		oidc.params.auth_req_id,
		{ ignoreExpiration: true }
	);

	if (!request) {
		throw new InvalidGrant('backchannel authentication request not found');
	}

	if (request.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

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

	if (request.isExpired) {
		throw new ExpiredToken('backchannel authentication request is expired');
	}

	if (!request.payload.grantId && !request.payload.error) {
		throw new AuthorizationPending();
	}

	if (request.payload.consumed) {
		await revoke({ oidc }, request.payload.grantId);
		throw new InvalidGrant(
			'backchannel authentication request already consumed'
		);
	}

	await request.consume();

	if (request.payload.error) {
		const className = upperFirst(camelCase(request.payload.error));
		if (errors[className]) {
			throw new errors[className](request.payload.errorDescription);
		}
		throw new errors.CustomOIDCProviderError(
			request.payload.error,
			request.payload.errorDescription
		);
	}

	const grant = await Grant.find(request.payload.grantId, {
		ignoreExpiration: true
	});

	if (!grant) {
		throw new InvalidGrant('grant not found');
	}

	if (grant.isExpired) {
		throw new InvalidGrant('grant is expired');
	}

	if (grant.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	oidc.entity('BackchannelAuthenticationRequest', request);
	oidc.entity('Grant', grant);

	const account = await findAccount(
		{ oidc },
		request.payload.accountId,
		request
	);

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
		accountId: account.accountId,
		client: oidc.client,
		expiresWithSession: request.payload.expiresWithSession,
		grantId: request.payload.grantId,
		gty,
		sessionUid: request.payload.sessionUid,
		sid: request.payload.sid
	});

	if (oidc.client.tlsClientCertificateBoundAccessTokens) {
		at.setThumbprint('x5t', cert);
	}

	if (dPoP) {
		at.setThumbprint('jkt', dPoP.thumbprint);
	}

	const resource = await resolveResource({ oidc }, request, {
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
		at.scope = grant.getResourceScopeFiltered(resource, request.scopes);
	} else {
		at.claims = request.payload.claims;
		at.scope = grant.getOIDCScopeFiltered(request.scopes);
	}

	oidc.entity('AccessToken', at);
	const accessToken = await at.save();

	let refreshToken;
	if (await issueRefreshToken({ oidc }, oidc.client, request)) {
		const rt = new RefreshToken({
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
	if (request.scopes.has('openid')) {
		const claims = filterClaims(request.payload.claims, 'id_token', grant);
		const rejected = grant.getRejectedOIDCClaims();
		const token = new IdToken(oidc.client, {
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
		});

		if (
			conformIdTokenClaims &&
			ApplicationConfig['userinfo.enabled'] &&
			!at.aud
		) {
			token.scope = 'openid';
		} else {
			token.scope = grant.getOIDCScopeFiltered(request.scopes);
		}

		token.mask = claims;
		token.rejected = rejected;

		token.set('nonce', request.payload.nonce);
		token.set('sid', request.payload.sid);

		idToken = await token.issue({ use: 'idtoken' });
	}

	return {
		access_token: accessToken,
		expires_in: at.expiration,
		id_token: idToken,
		refresh_token: refreshToken,
		scope: request.payload.scope ? at.scope : at.payload.scope || undefined,
		token_type: at.tokenType
	};
};
