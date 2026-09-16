import { Elysia, Static, t } from 'elysia';
import { InvalidClientAuth } from 'lib/helpers/errors.js';
import { requestBucketFor } from 'lib/admin/auth/bucketAddress.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { tokenAuth } from 'lib/shared/token_auth.js';

export const authHeaders = t.Object({
	authorization: t.Optional(t.String()),
	dpop: t.Optional(t.String())
});

export const authParams = t.Object({
	client_id: t.Optional(t.String()),
	client_assertion: t.Optional(t.String()),
	client_assertion_type: t.Optional(t.String()),
	client_secret: t.Optional(t.String())
});

export type authParamsType = Record<string, unknown> &
	Static<typeof authParams>;

export function withBody<T extends Record<string, unknown>>(
	oidc: OIDCContext<authParamsType>,
	body: T
): OIDCContext<authParamsType & T> {
	const typed = oidc as unknown as OIDCContext<authParamsType & T>;
	typed.params = body as authParamsType & T;
	return typed;
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

export const AuthPlugin = new Elysia().derive(
	{ as: 'scoped' },
	async function ({ headers, route, body, params }) {
		if (!isObject(body)) {
			throw new InvalidClientAuth('Request body must be an object');
		}
		/*
		 * Resolved here rather than in each handler because every client-authenticated endpoint takes its
		 * context from this one derive — the token, introspection, revocation, pushed-request, device and
		 * backchannel endpoints all do. One place to resolve the address is also one place that cannot be
		 * forgotten when another such endpoint is added.
		 *
		 * `params.bucket` exists only on the prefixed mount; its absence is the bare address, which is
		 * the default bucket's.
		 */
		const bucket = await requestBucketFor(
			(params as { bucket?: string } | undefined)?.bucket
		);
		const oidc = new OIDCContext(body, headers, route, bucket);
		await tokenAuth(body, headers, oidc);
		return { oidc };
	}
);
