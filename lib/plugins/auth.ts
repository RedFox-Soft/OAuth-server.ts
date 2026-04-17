import { Elysia, Static, t } from 'elysia';
import { InvalidClientAuth } from 'lib/helpers/errors.js';
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

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

export const AuthPlugin = new Elysia().derive(
	{ as: 'scoped' },
	async function ({ headers, route, body }) {
		if (!isObject(body)) {
			throw new InvalidClientAuth('Request body must be an object');
		}
		const oidc = new OIDCContext(body, headers, route);
		await tokenAuth(body, headers, oidc);
		return { oidc };
	}
);
