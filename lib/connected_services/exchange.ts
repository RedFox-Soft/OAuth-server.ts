import { guardedFetch, readBounded } from '../shared/egress.js';
import {
	MAX_UPSTREAM_DOCUMENT_BYTES,
	UPSTREAM_TIMEOUT_MS
} from '../federation/consts.js';
import epochTime from '../helpers/epoch_time.js';
import type { ResolvedService } from './catalogue.js';
import { valueAt } from './paths.js';
import { upstreamIdIn } from './identity.js';

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
	response: Record<string, unknown>,
	path: string | undefined = service.tokenPath,
	/*
	 * Only for a refresh, whose shape the provider may not document (catalogue `refreshTokenPath`). Never for a code
	 * exchange: Slack's top level holds the bot's token, not the person's.
	 */
	orTopLevel = false
): IssuedTokens {
	let holder: unknown = response;
	if (path) {
		const nested = valueAt(response, path);
		holder = nested !== undefined || !orTopLevel ? nested : response;
	}
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
	const answer = await tokenRequest(service, client, body);
	// Slack answers 200 with `ok: false` for a refused code.
	if (answer.ok === false || typeof answer.error === 'string') {
		throw new ConnectExchangeError('refused');
	}
	return tokensOf(service, answer);
}

/* Client authentication as the service resolved it; the answer parsed, or why there was none. */
async function tokenRequest(
	service: ResolvedService,
	client: { clientId: string; clientSecret: string },
	body: URLSearchParams
): Promise<Record<string, unknown>> {
	const answer = await rawTokenRequest(service, client, body);
	if (answer.kind === 'refused') throw new ConnectExchangeError('refused');
	return answer.body;
}

type RawAnswer =
	| { kind: 'answered'; body: Record<string, unknown> }
	| { kind: 'refused'; status: number; body?: Record<string, unknown> };

async function rawTokenRequest(
	service: ResolvedService,
	client: { clientId: string; clientSecret: string },
	body: URLSearchParams
): Promise<RawAnswer> {
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
	let status: number;
	try {
		const response = await guardedFetch(service.tokenEndpoint, {
			method: 'POST',
			headers,
			body,
			timeoutMs: UPSTREAM_TIMEOUT_MS
		});
		status = response.status;
		text = await readBounded(response, MAX_UPSTREAM_DOCUMENT_BYTES);
	} catch {
		throw new ConnectExchangeError('unreachable');
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		if (status < 200 || status >= 300) return { kind: 'refused', status };
		throw new ConnectExchangeError('malformed');
	}
	const answer =
		typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: undefined;
	if (status < 200 || status >= 300) {
		return { kind: 'refused', status, ...(answer ? { body: answer } : {}) };
	}
	if (!answer) throw new ConnectExchangeError('malformed');
	return { kind: 'answered', body: answer };
}

// ---------------------------------------------------------------- refresh (specs/118 R10)

export type RefreshOutcome =
	| { kind: 'refreshed'; tokens: IssuedTokens }
	| { kind: 'rejected' }
	| { kind: 'unavailable' }
	| { kind: 'identity_changed' };

/*
 * The answers that mean the person's refresh token is gone for good: RFC 6749 §5.2 `invalid_grant`, and Slack's own
 * words for a spent, revoked or expired one (https://docs.slack.dev/reference/methods/oauth.v2.access). Anything
 * else, including a refusal of this project's own credentials, leaves the account as it is: the person did nothing.
 */
const GONE = new Set([
	'invalid_grant',
	/* GitHub's, answered with status 200 (docs.github.com, "Refreshing user access tokens"). */
	'bad_refresh_token',
	'invalid_refresh_token',
	'token_revoked',
	'token_expired'
]);

export async function refreshUpstream(
	service: ResolvedService,
	client: { clientId: string; clientSecret: string },
	refreshToken: string,
	upstreamId: string
): Promise<RefreshOutcome> {
	const body = new URLSearchParams({
		grant_type: 'refresh_token',
		refresh_token: refreshToken,
		client_id: client.clientId
	});
	let answer: RawAnswer;
	try {
		answer = await rawTokenRequest(service, client, body);
	} catch {
		return { kind: 'unavailable' };
	}
	const error = answer.body?.error;
	if (answer.kind === 'refused') {
		return answer.status >= 400 &&
			answer.status < 500 &&
			answer.status !== 429 &&
			typeof error === 'string' &&
			GONE.has(error)
			? { kind: 'rejected' }
			: { kind: 'unavailable' };
	}
	if (answer.body.ok === false || typeof error === 'string') {
		return typeof error === 'string' && GONE.has(error)
			? { kind: 'rejected' }
			: { kind: 'unavailable' };
	}
	const named = upstreamIdIn(service, answer.body);
	if (named !== undefined && named !== upstreamId) {
		return { kind: 'identity_changed' };
	}
	try {
		return {
			kind: 'refreshed',
			tokens: tokensOf(
				service,
				answer.body,
				service.refreshTokenPath ?? service.tokenPath,
				true
			)
		};
	} catch {
		return { kind: 'unavailable' };
	}
}
