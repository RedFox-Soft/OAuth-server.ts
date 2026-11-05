import {
	issuingBucket,
	servingBucketIdOf
} from '../admin/auth/bucketAddress.js';
import { pairwiseIdentifier } from '../addon/index.js';
import type { ProtectedResource } from '../adapters/types.js';
import { ISSUER } from '../configs/env.js';
import { issuerFor } from '../configs/issuer.js';
import * as JWT from '../helpers/jwt.js';
import { keysFor } from '../keys/issuer_keys.js';
import { AccessToken } from '../models/access_token.js';
import { Client } from '../models/client.js';
import { ClientCredentials } from '../models/client_credentials.js';
import { Grant } from '../models/grant.js';
import { ROOT_NAMESPACE } from '../resources/namespace.js';

/*
 * The access token a request to an API carries, read as the API itself would read it had it followed the
 * checklist this server gives it (specs/107, specs/123 research R2): a self-contained token by the keys and issuer
 * its tokens come from, its audience, its lifetime and its type; an opaque one by the store, as introspection
 * reads it. A token bound to a key is refused, because the proof that would make it usable was made for the
 * request to the API, which the proxy never forwards (R4).
 */

export type BearerRefusal =
	'missing_token' | 'invalid_token' | 'bound_token_unsupported';

export type Presented =
	| {
			ok: true;
			/* The `sub` the API would read off the token itself. */
			subject: string;
			clientId: string;
			/* The token's `scope`, as it carries it. */
			scope: string;
			scopes: ReadonlySet<string>;
	  }
	| { ok: false; reason: BearerRefusal };

const ACCESS_TOKEN_TYPES = new Set(['at+jwt', 'application/at+jwt']);

type Api = Pick<ProtectedResource, 'identifier' | 'namespace' | 'bucketId'>;

function refused(reason: BearerRefusal): Presented {
	return { ok: false, reason };
}

function scopesOf(scope: unknown): { scope: string; scopes: Set<string> } {
	const text = typeof scope === 'string' ? scope : '';
	return { scope: text, scopes: new Set(text.split(' ').filter(Boolean)) };
}

/*
 * The one token the request presents, or why there is none to read. Only the `Authorization` header counts: a
 * token in the query or the body is a credential the API was never asked to accept that way (RFC 6750 §2 lets a
 * resource refuse both), and the proxy forwards no body anyway. Two headers arrive joined by a comma, which no
 * token contains, so a value holding one is two credentials and is no single answer.
 */
function presentedToken(
	request: Request
): { token: string } | { reason: BearerRefusal } {
	const header = request.headers.get('authorization');
	if (header === null || header.includes(',')) {
		return { reason: 'missing_token' };
	}
	const match = /^([A-Za-z]+) +([^ ]+)$/.exec(header.trim());
	if (!match) return { reason: 'missing_token' };
	const scheme = match[1].toLowerCase();
	if (scheme === 'dpop') return { reason: 'bound_token_unsupported' };
	if (scheme !== 'bearer') return { reason: 'missing_token' };
	return { token: match[2] };
}

/* The issuer the API's tokens carry, and the bucket whose keys sign them: the project's, or the root's. */
export async function apiIssuerOf(api: Pick<Api, 'namespace'>) {
	const bucket = await issuingBucket(
		api.namespace === ROOT_NAMESPACE ? undefined : api.namespace
	);
	return {
		bucket,
		issuer: api.namespace === ROOT_NAMESPACE ? ISSUER : issuerFor(bucket)
	};
}

/*
 * A self-contained token is not stored, so it is checked as its API checks it, and never against the grant it came
 * from (FR-012): a revoked one is usable here until it expires, which is why the console recommends an opaque
 * token or a short lifetime for an API behind the proxy.
 */
async function fromJwt(token: string, api: Api): Promise<Presented> {
	const { bucket, issuer } = await apiIssuerOf(api);
	let verified;
	try {
		verified = await JWT.verify(token, (await keysFor(bucket)).verification, {
			issuer,
			subject: true
		});
	} catch {
		return refused('invalid_token');
	}
	const { payload, header } = verified;
	const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
	if (!ACCESS_TOKEN_TYPES.has(typ)) return refused('invalid_token');
	const aud: unknown = payload.aud;
	const forThisApi =
		aud === api.identifier ||
		(Array.isArray(aud) && aud.length === 1 && aud[0] === api.identifier);
	if (!forThisApi) return refused('invalid_token');
	if (payload.cnf !== undefined) return refused('bound_token_unsupported');
	const clientId: unknown = payload.client_id;
	const sub: unknown = payload.sub;
	if (typeof clientId !== 'string' || typeof sub !== 'string') {
		return refused('invalid_token');
	}
	return { ok: true, subject: sub, clientId, ...scopesOf(payload.scope) };
}

/*
 * An opaque token is a stored record, read in introspection's order: present and unexpired (an ended session or a
 * revocation leaves nothing to find), issued where the API's tokens are issued, for this API, and — when it names a
 * grant — that grant still standing for the same client and person.
 */
async function fromRecord(token: string, api: Api): Promise<Presented> {
	const record =
		(await AccessToken.tryFind(token)) ??
		(await ClientCredentials.tryFind(token));
	if (!record?.isValid) return refused('invalid_token');
	const payload: {
		clientId: string;
		bucketId?: string;
		aud?: string;
		scope?: string;
		accountId?: string;
		grantId?: string;
		jkt?: string;
		'x5t#S256'?: string;
	} = record.payload;
	if (
		(await servingBucketIdOf(payload.bucketId)) !==
			(await servingBucketIdOf(api.bucketId)) ||
		payload.aud !== api.identifier
	) {
		return refused('invalid_token');
	}
	if (payload.grantId) {
		const grant = await Grant.tryFind(payload.grantId, {
			ignoreExpiration: true
		});
		if (
			!grant ||
			grant.isExpired ||
			grant.payload.clientId !== payload.clientId ||
			grant.payload.accountId !== payload.accountId
		) {
			return refused('invalid_token');
		}
	}
	if (payload.jkt || payload['x5t#S256']) {
		return refused('bound_token_unsupported');
	}
	let subject = payload.clientId;
	if (payload.accountId) {
		subject = payload.accountId;
		let client;
		try {
			client = await Client.find(payload.clientId);
		} catch {
			return refused('invalid_token');
		}
		if (client.subjectType === 'pairwise') {
			subject = await pairwiseIdentifier(subject, client);
		}
	}
	return {
		ok: true,
		subject,
		clientId: payload.clientId,
		...scopesOf(payload.scope)
	};
}

export async function readBearer(
	api: Api,
	request: Request
): Promise<Presented> {
	const presented = presentedToken(request);
	if ('reason' in presented) return refused(presented.reason);
	return presented.token.split('.').length === 3
		? fromJwt(presented.token, api)
		: fromRecord(presented.token, api);
}
