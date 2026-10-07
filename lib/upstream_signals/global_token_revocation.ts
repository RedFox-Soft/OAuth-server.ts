import { Elysia, t } from 'elysia';

import { getBucketStore } from '../adapters/index.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import { issuerFor } from '../configs/issuer.js';
import { routeNames } from '../consts/param_list.js';
import { hostOfRequest } from '../consts/request_host.js';
import { eventBus } from '../event_bus.js';
import {
	InvalidRequest,
	InvalidToken,
	OIDCProviderError,
	RateLimited,
	UnknownSubject,
	UpstreamKeysUnavailable,
	UpstreamNotPermitted
} from '../helpers/errors.js';
import { chargeFailedCredential } from '../helpers/unauthenticated_charge.js';
import { originOf } from '../plugins/rateLimit.js';
import { authenticateUpstream } from './assertion.js';
import { endAccessForUpstream } from './end_access.js';
import { resolveReachableUser, type SubjectIdentifier } from './subject.js';

/*
 * Global Token Revocation at `<bucket issuer>/global-token-revocation` (specs/072): a bucket's upstream identity
 * provider, opted in, asks for everything one of its users holds here to end. The request Okta Universal Logout
 * documents is the target, with draft-parecki-oauth-global-token-revocation-06 — an individual draft that
 * expired unadopted on 2026-08-28 — as the reference for what Okta leaves unstated. The whole surface sits behind
 * `globalTokenRevocation.enabled` for that reason (Constitution Principle I), gated in route_classification.ts.
 *
 * This file is only the wire format: the bearer assertion and the `sub_id` body. Who may ask, and whom they may
 * name, is lib/upstream_signals/assertion.ts and subject.ts, shared with the formats that come after it.
 */

/* Okta's `typ`. The draft names none; absent and the generic `JWT` are accepted too (assertion.ts). */
const ASSERTION_TYPES = ['global-token-revocation+jwt'];

/*
 * The two subject identifier formats (RFC 9493) Okta sends. Strict inside `sub_id`, because a format we do not
 * resolve must be refused rather than read as nobody; tolerant of other top-level members, which the draft
 * neither defines nor forbids.
 */
const RevocationBody = t.Object(
	{
		sub_id: t.Union(
			[
				t.Object(
					{
						format: t.Literal('iss_sub'),
						iss: t.String({ minLength: 1 }),
						sub: t.String({ minLength: 1 })
					},
					{ additionalProperties: false }
				),
				t.Object(
					{
						format: t.Literal('email'),
						email: t.String({ minLength: 3 })
					},
					{ additionalProperties: false }
				)
			],
			{
				error:
					'sub_id must be a subject identifier in the iss_sub or email format'
			}
		)
	},
	{ additionalProperties: true }
);

/* The reason a refusal is reported under, for an operator; never sent to the caller. */
function reasonOf(error: unknown): string {
	if (error instanceof UnknownSubject) return 'unknown_subject';
	if (error instanceof UpstreamNotPermitted) return 'not_permitted';
	if (error instanceof UpstreamKeysUnavailable) return 'keys_unavailable';
	if (error instanceof InvalidToken) {
		return `credential:${error.error_detail ?? 'invalid'}`;
	}
	if (error instanceof InvalidRequest) return 'malformed_request';
	return 'error';
}

function bearerOf(request: Request): string {
	const authorization = request.headers.get('authorization') ?? '';
	const match = /^Bearer\s+(\S+)$/i.exec(authorization.trim());
	if (!match?.[1]) throw new InvalidToken('no_credential');
	return match[1];
}

async function revoke(
	request: Request,
	slug: string | undefined,
	server: unknown,
	subject: SubjectIdentifier
): Promise<void> {
	const addressed = await requestBucketFor(slug, hostOfRequest(request));
	const audience = `${issuerFor(addressed)}${routeNames.global_token_revocation}`;
	/* A bucket with no stored record holds no providers, so nobody can be authenticated for it. */
	const bucket = await getBucketStore().find(addressed._id);
	try {
		if (!bucket) throw new InvalidToken('unknown_provider');
		const { provider } = await (async () => {
			try {
				return await authenticateUpstream(bucket, bearerOf(request), {
					audience,
					types: ASSERTION_TYPES,
					replayNamespace: 'gtr',
					permits: (candidate) =>
						candidate.acceptsGlobalTokenRevocation === true
				});
			} catch (error) {
				/* The strict per-origin charge, shared with SCIM: a guesser gets no more room here than at /token. */
				if (error instanceof InvalidToken) {
					chargeFailedCredential(
						originOf(request, server),
						(retryAfterSeconds) => new RateLimited(retryAfterSeconds, 'strict')
					);
				}
				throw error;
			}
		})();

		const user = await resolveReachableUser(bucket, provider, subject);
		if (!user) throw new UnknownSubject();
		await endAccessForUpstream(bucket, provider, user);
		eventBus.emit('upstream.revocation.success', {
			bucketId: bucket._id,
			providerId: provider.id,
			accountId: user._id
		});
	} catch (error) {
		if (error instanceof OIDCProviderError && error.status < 500) {
			eventBus.emit('upstream.revocation.refused', {
				bucketId: addressed._id,
				reason: reasonOf(error)
			});
		}
		throw error;
	}
}

export const globalTokenRevocation = new Elysia({
	name: 'global-token-revocation'
}).post(
	routeNames.global_token_revocation,
	async ({ request, params, server, body, set }) => {
		/* Absent on the bare route: Elysia passes no params object where the path has none. */
		const slug = (params as Record<string, string | undefined> | undefined)
			?.bucket;
		try {
			await revoke(request, slug, server, body.sub_id);
		} catch (error) {
			/*
			 * RFC 6750 §3: a refused credential is answered with a challenge. The shared handler adds a detailed
			 * one when a Bearer header was sent; a request that sent none still has to learn the scheme.
			 */
			if (error instanceof InvalidToken) {
				set.headers['WWW-Authenticate'] = 'Bearer error="invalid_token"';
			}
			throw error;
		}
		set.status = 204;
		return undefined;
	},
	{ body: RevocationBody }
);
