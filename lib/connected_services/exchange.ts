import { guardedFetch, readBounded } from '../shared/egress.js';
import {
	MAX_UPSTREAM_DOCUMENT_BYTES,
	UPSTREAM_TIMEOUT_MS
} from '../federation/consts.js';
import epochTime from '../helpers/epoch_time.js';
import type { ResolvedService } from './catalogue.js';
import { valueAt } from './paths.js';

/*
 * Redeeming a connect flow's code (specs/117 R6). Unlike the sign-in exchange, which keeps only the ID token,
 * this keeps the person's tokens: they are what a connected account is.
 */

export class ConnectExchangeError extends Error {
	constructor(readonly reason: 'unreachable' | 'malformed' | 'refused') {
		super(`the provider did not issue tokens: ${reason}`);
	}
}

export interface IssuedTokens {
	accessToken: string;
	refreshToken?: string;
	tokenType: string;
	accessTokenExpiresAt?: number;
	refreshTokenExpiresAt?: number;
	/* The scopes the provider says it granted, or absent when it says nothing usable. */
	grantedScopes?: string[];
	idToken?: string;
	/* The whole answer, for an identity read from the token response; never stored. */
	response: Record<string, unknown>;
}

function seconds(value: unknown): number | undefined {
	const number = typeof value === 'string' ? Number(value) : value;
	return typeof number === 'number' && Number.isFinite(number) && number > 0
		? Math.floor(number)
		: undefined;
}

export function tokensOf(
	service: ResolvedService,
	response: Record<string, unknown>
): IssuedTokens {
	const holder = service.tokenPath
		? valueAt(response, service.tokenPath)
		: response;
	if (typeof holder !== 'object' || holder === null) {
		throw new ConnectExchangeError('malformed');
	}
	const tokens = holder as Record<string, unknown>;
	if (typeof tokens.access_token !== 'string' || tokens.access_token === '') {
		throw new ConnectExchangeError('malformed');
	}
	const now = epochTime();
	const expiresIn = seconds(tokens.expires_in);
	const refreshExpiresIn = seconds(tokens.refresh_token_expires_in);
	const scope = tokens.scope;
	/*
	 * An empty list is a provider saying nothing (a GitHub App always answers `""`), not a provider granting
	 * nothing: the person approved a consent screen that listed the scopes asked for.
	 */
	const grantedScopes =
		typeof scope === 'string'
			? scope
					.split(service.responseScopeSeparator)
					.map((item) => item.trim())
					.filter(Boolean)
			: [];
	return {
		accessToken: tokens.access_token,
		...(typeof tokens.refresh_token === 'string' && tokens.refresh_token
			? { refreshToken: tokens.refresh_token }
			: {}),
		tokenType:
			typeof tokens.token_type === 'string' && tokens.token_type
				? tokens.token_type
				: 'Bearer',
		...(expiresIn ? { accessTokenExpiresAt: now + expiresIn } : {}),
		...(refreshExpiresIn
			? { refreshTokenExpiresAt: now + refreshExpiresIn }
			: {}),
		...(grantedScopes.length > 0 ? { grantedScopes } : {}),
		...(typeof response.id_token === 'string'
			? { idToken: response.id_token }
			: {}),
		response
	};
}

/*
 * Client authentication as the service resolved it, through the egress boundary with the sign-in exchange's
 * bounds. `accept: application/json` because GitHub answers form-encoded without it.
 */
export async function exchangeConnectCode(
	service: ResolvedService,
	client: { clientId: string; clientSecret: string },
	code: string,
	redirectUri: string,
	codeVerifier?: string
): Promise<IssuedTokens> {
	const body = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: redirectUri,
		client_id: client.clientId
	});
	if (codeVerifier) body.set('code_verifier', codeVerifier);
	const headers: Record<string, string> = {
		'content-type': 'application/x-www-form-urlencoded',
		accept: 'application/json'
	};
	if (service.tokenAuth === 'post') {
		body.set('client_secret', client.clientSecret);
	} else {
		const credentials = `${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.clientSecret)}`;
		headers.authorization = `Basic ${Buffer.from(credentials).toString('base64')}`;
	}

	let text: string;
	try {
		const response = await guardedFetch(service.tokenEndpoint, {
			method: 'POST',
			headers,
			body,
			timeoutMs: UPSTREAM_TIMEOUT_MS
		});
		if (!response.ok) throw new ConnectExchangeError('refused');
		text = await readBounded(response, MAX_UPSTREAM_DOCUMENT_BYTES);
	} catch (err) {
		if (err instanceof ConnectExchangeError) throw err;
		throw new ConnectExchangeError('unreachable');
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new ConnectExchangeError('malformed');
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		throw new ConnectExchangeError('malformed');
	}
	const answer = parsed as Record<string, unknown>;
	// Slack answers 200 with `ok: false` for a refused code.
	if (answer.ok === false || typeof answer.error === 'string') {
		throw new ConnectExchangeError('refused');
	}
	return tokensOf(service, answer);
}
