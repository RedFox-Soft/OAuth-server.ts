import crypto from 'node:crypto';
import os from 'node:os';

import { mustChange } from './_warn.ts';
import nanoid from '../helpers/nanoid.ts';

export function idFactory(ctx) {
	return nanoid();
}

export async function secretFactory(ctx) {
	return crypto.randomBytes(64).toString('base64url');
}

export async function expiresWithSession(ctx, code) {
	return !code.scopes.has('offline_access');
}

export async function issueRefreshToken(ctx, client, code) {
	return (
		client.grantTypeAllowed('refresh_token') &&
		code.scopes.has('offline_access')
	);
}

export async function pairwiseIdentifier(accountId, client) {
	mustChange(
		'pairwiseIdentifier',
		'provide an implementation for pairwise identifiers, the default one uses `os.hostname()` as salt and is therefore not fit for anything else than development'
	);
	return crypto
		.createHash('sha256')
		.update(client.sectorIdentifier)
		.update(accountId)
		.update(os.hostname()) // put your own unique salt here, or implement other mechanism
		.digest('hex');
}

export function rotateRefreshToken(ctx) {
	const { RefreshToken: refreshToken, Client: client } = ctx.oidc.entities;

	// cap the maximum amount of time a refresh token can be
	// rotated for up to 1 year, afterwards its TTL is final
	if (refreshToken.totalLifetime() >= 365.25 * 24 * 60 * 60) {
		return false;
	}

	// rotate non sender-constrained public client refresh tokens
	if (
		client.clientAuthMethod === 'none' &&
		!refreshToken.isSenderConstrained()
	) {
		return true;
	}

	// rotate if the token is nearing expiration (it's beyond 70% of its lifetime)
	return refreshToken.ttlPercentagePassed() >= 70;
}
