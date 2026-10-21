import type { X509Certificate } from 'node:crypto';

import type { TokenParams } from '../actions/token.js';
import { findAccount } from '../addon/account.js';
import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import type { Account, OIDCContext } from '../helpers/oidc_context.js';
import revoke from '../helpers/revoke.js';
import type { DPoPProof } from '../helpers/validate_dpop.js';
import { Grant } from '../models/grant.js';
import { RefreshToken } from '../models/refresh_token.js';

/*
 * What makes a refresh token usable, in one place: the refresh grant redeems one and the token exchange
 * accepts one as the subject of an ID-JAG (specs/108), and ID-JAG §4.3.3 asks the exchange to validate it
 * "the same way it would for a standard refresh_token grant". Two copies of these checks would drift the first
 * time one of them gained a check.
 *
 * It refuses with its own error so each caller answers in its own terms — `invalid_grant` for the refresh
 * grant, `invalid_request` for the exchange (RFC 8693 §2.2.2) — with the same reason underneath. It sets no
 * entity on the context: what a request did with the token is the caller's to record.
 */
export class RefreshTokenRefused extends Error {
	constructor(readonly reason: string) {
		super(reason);
	}
}

export interface UsableRefreshToken {
	refreshToken: RefreshToken;
	grant: Grant;
	account: Account;
	cert: X509Certificate | undefined;
}

/*
 * A rotated token presented again revokes the whole grant, whether the earlier use was a request that has
 * finished or one racing this one — what a stolen token's holder and its owner refreshing at once looks like,
 * which must not yield two live chains. Wherever the token is presented: an exchange is a use too.
 */
export async function revokeReused(
	oidc: OIDCContext<TokenParams>,
	refreshToken: RefreshToken
): Promise<RefreshTokenRefused> {
	const { grantId } = refreshToken.payload;
	await Promise.all([refreshToken.destroy(), grantId && revoke(grantId, oidc)]);
	return new RefreshTokenRefused('refresh token already used');
}

export async function usableRefreshToken(
	oidc: OIDCContext<TokenParams>,
	value: string,
	dPoP: DPoPProof
): Promise<UsableRefreshToken> {
	const { client } = oidc;

	const refreshToken = await RefreshToken.find(value, {
		ignoreExpiration: true,
		error: new RefreshTokenRefused('refresh token not found')
	});

	if (refreshToken.payload.clientId !== client.clientId) {
		throw new RefreshTokenRefused('client mismatch');
	}

	if (refreshToken.isExpired) {
		throw new RefreshTokenRefused('refresh token is expired');
	}

	let cert: X509Certificate | undefined;
	if (
		client.tlsClientCertificateBoundAccessTokens ||
		refreshToken.payload['x5t#S256']
	) {
		cert = oidc.getClientCertificate();
		if (!cert) {
			throw new RefreshTokenRefused(
				'mutual TLS client certificate not provided'
			);
		}
	}

	if (!dPoP && client.dpopBoundAccessTokens) {
		throw new RefreshTokenRefused('DPoP proof JWT not provided');
	}

	if (
		refreshToken.payload['x5t#S256'] &&
		(!cert || refreshToken.payload['x5t#S256'] !== certificateThumbprint(cert))
	) {
		throw new RefreshTokenRefused('failed x5t#S256 verification');
	}

	const { grantId } = refreshToken.payload;
	if (!grantId) {
		throw new RefreshTokenRefused('grant not found');
	}
	const grant = await Grant.find(grantId, {
		ignoreExpiration: true,
		error: new RefreshTokenRefused('grant not found')
	});

	if (grant.isExpired) {
		throw new RefreshTokenRefused('grant is expired');
	}

	if (grant.payload.clientId !== client.clientId) {
		throw new RefreshTokenRefused('client mismatch');
	}

	if (
		refreshToken.payload.jkt &&
		(!dPoP || refreshToken.payload.jkt !== dPoP.thumbprint)
	) {
		throw new RefreshTokenRefused('failed jkt verification');
	}

	const account = await findAccount(
		oidc,
		refreshToken.payload.accountId,
		refreshToken
	);

	if (!account) {
		throw new RefreshTokenRefused(
			'refresh token invalid (referenced account not found)'
		);
	}

	if (refreshToken.payload.accountId !== grant.payload.accountId) {
		throw new RefreshTokenRefused('accountId mismatch');
	}

	if (refreshToken.payload.consumed) {
		throw await revokeReused(oidc, refreshToken);
	}

	return { refreshToken, grant, account, cert };
}
