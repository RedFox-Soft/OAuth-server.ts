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
import { DeviceCode } from 'lib/models/device_code.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Grant } from 'lib/models/grant.js';
import ResourceServer from 'lib/helpers/resource_server.js';

const { AuthorizationPending, ExpiredToken, InvalidGrant } = errors;

export const gty = 'device_code';

export const handler = async function deviceCodeHandler(oidc, dPoP) {
	presence(oidc, 'device_code');

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

	const code = await DeviceCode.find(oidc.params.device_code, {
		ignoreExpiration: true,
		error: new InvalidGrant('device code not found')
	});

	if (code.payload.clientId !== oidc.client.clientId) {
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

	if (code.isExpired) {
		throw new ExpiredToken('device code is expired');
	}

	if (!code.payload.accountId && !code.payload.error) {
		throw new AuthorizationPending();
	}

	if (code.payload.consumed) {
		await revoke(oidc, code.payload.grantId);
		throw new InvalidGrant('device code already consumed');
	}

	await code.consume();

	if (code.payload.error) {
		const className = upperFirst(camelCase(code.payload.error));
		if (errors[className]) {
			throw new errors[className](code.payload.errorDescription);
		}
		throw new errors.CustomOIDCProviderError(
			code.payload.error,
			code.payload.errorDescription
		);
	}

	const grant = await Grant.find(code.payload.grantId, {
		ignoreExpiration: true,
		error: new InvalidGrant('grant not found')
	});

	if (grant.isExpired) {
		throw new InvalidGrant('grant is expired');
	}

	if (grant.payload.clientId !== oidc.client.clientId) {
		throw new InvalidGrant('client mismatch');
	}

	oidc.entity('DeviceCode', code);
	oidc.entity('Grant', grant);

	const account = await findAccount({ oidc }, code.payload.accountId, code);

	if (!account) {
		throw new InvalidGrant(
			'device code invalid (referenced account not found)'
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

	if (dPoP) {
		at.setThumbprint('jkt', dPoP.thumbprint);
	}

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
		at.resourceServer = new ResourceServer(resource, resourceServerInfo);
		at.payload.scope = grant.getResourceScopeFiltered(resource, code.scopes);
	} else {
		at.payload.claims = code.payload.claims;
		at.payload.scope = grant.getOIDCScopeFiltered(code.scopes);
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
			sid: code.payload.sid
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
			...{
				acr: code.payload.acr,
				amr: code.payload.amr,
				auth_time: code.payload.authTime
			}
		});

		if (
			conformIdTokenClaims &&
			ApplicationConfig['userinfo.enabled'] &&
			!at.aud
		) {
			token.scope = 'openid';
		} else {
			token.scope = grant.getOIDCScopeFiltered(code.scopes);
		}

		token.mask = claims;
		token.rejected = rejected;

		token.set('nonce', code.payload.nonce);
		token.set('sid', code.payload.sid);

		idToken = await token.issue('idtoken');
	}

	return {
		access_token: accessToken,
		expires_in: at.expiration,
		id_token: idToken,
		refresh_token: refreshToken,
		scope: code.payload.scope || at.payload.scope || undefined,
		token_type: at.tokenType
	};
};
