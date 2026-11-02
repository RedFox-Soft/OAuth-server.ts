import { guardedFetch, readBounded } from '../shared/egress.js';
import {
	MAX_UPSTREAM_DOCUMENT_BYTES,
	UPSTREAM_TIMEOUT_MS
} from '../federation/consts.js';
import { verifyFederatedIdToken } from '../federation/verifyIdToken.js';
import type { ResolvedService } from './catalogue.js';
import type { IssuedTokens } from './exchange.js';
import { textAt } from './paths.js';

/*
 * Who the connected account is at the provider (specs/117 R6): a stable key, and a label for people. The key
 * decides whether a callback is a reconnect or a new account, so it is never a login or an address, which a
 * person can change; the label is display only.
 */

export class IdentityUnavailable extends Error {
	constructor(readonly reason: string) {
		super(`the provider did not say who the account is: ${reason}`);
	}
}

export interface UpstreamAccount {
	upstreamId: string;
	label: string;
}

const LABEL_LIMIT = 200;

function keyOf(document: unknown, paths: readonly string[]): string {
	const parts = paths.map((path) => textAt(document, path));
	if (parts.some((part) => part === undefined)) {
		throw new IdentityUnavailable('no account id');
	}
	return parts.join(':');
}

function labelOf(document: unknown, path: string, fallback: string): string {
	return (textAt(document, path) ?? fallback).slice(0, LABEL_LIMIT);
}

async function fromEndpoint(
	url: string,
	accessToken: string
): Promise<unknown> {
	try {
		const response = await guardedFetch(url, {
			headers: {
				authorization: `Bearer ${accessToken}`,
				accept: 'application/json',
				// GitHub refuses an API request without one.
				'user-agent': 'FoxAuth'
			},
			timeoutMs: UPSTREAM_TIMEOUT_MS
		});
		if (!response.ok)
			throw new IdentityUnavailable(`status ${response.status}`);
		return JSON.parse(await readBounded(response, MAX_UPSTREAM_DOCUMENT_BYTES));
	} catch (err) {
		if (err instanceof IdentityUnavailable) throw err;
		throw new IdentityUnavailable('unreachable');
	}
}

/*
 * The account a refresh's answer names, when it names one without another request (specs/118 R10): the token
 * answer itself, or the claims of an ID token in it. Read, not verified: the answer came from the provider's own
 * token endpoint over TLS, and a mismatch only ever breaks the account, never grants anything.
 */
export function upstreamIdIn(
	service: ResolvedService,
	response: Record<string, unknown>
): string | undefined {
	const identity = service.identity;
	let document: unknown;
	if (identity.source === 'token') {
		document = response;
	} else if (
		identity.source === 'id_token' &&
		typeof response.id_token === 'string'
	) {
		try {
			const part = response.id_token.split('.')[1] ?? '';
			document = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
		} catch {
			return undefined;
		}
	} else {
		return undefined;
	}
	const parts = identity.idPaths.map((path) => textAt(document, path));
	return parts.every((part) => part !== undefined)
		? parts.join(':')
		: undefined;
}

export async function identify(
	service: ResolvedService,
	client: { clientId: string },
	tokens: IssuedTokens,
	nonce: string | undefined
): Promise<UpstreamAccount> {
	const identity = service.identity;
	let document: unknown;
	switch (identity.source) {
		case 'id_token': {
			if (!service.oidc || !nonce) throw new IdentityUnavailable('no id token');
			try {
				const assertion = await verifyFederatedIdToken(tokens.idToken, {
					metadata: service.oidc.metadata,
					clientId: client.clientId,
					nonce,
					...(service.oidc.acceptIssuer
						? { acceptIssuer: service.oidc.acceptIssuer }
						: {})
				});
				document = { ...assertion.claims, sub: assertion.subject };
			} catch {
				throw new IdentityUnavailable('id token rejected');
			}
			break;
		}
		case 'endpoint':
			document = await fromEndpoint(identity.url, tokens.accessToken);
			break;
		case 'token':
			document = tokens.response;
			break;
	}
	const upstreamId = keyOf(document, identity.idPaths);
	return {
		upstreamId,
		label: labelOf(document, identity.labelPath, upstreamId)
	};
}
