import { Elysia, t } from 'elysia';

import { provider } from 'lib/provider.js';
import instance from '../helpers/weak_cache.ts';
import { UnsupportedGrantType, InvalidRequest } from '../helpers/errors.ts';
import getTokenAuth from '../shared/token_auth.ts';
import { urlencoded as parseBody } from '../shared/selective_body.ts';
import rejectDupes from '../shared/reject_dupes.ts';
import paramsMiddleware from '../shared/assemble_params.ts';
import { globalConfiguration } from '../globalConfiguration.ts';

const grantTypeSet = new Set(['grant_type']);

export const tokenAction = new Elysia().post(
	globalConfiguration.routes.token,
	async ({ body, headers }) => {
		const ctx = {
			headers
		};
		const OIDCContext = provider.OIDCContext;
		ctx.oidc = new OIDCContext(ctx);
		ctx.oidc.params = body;
		ctx.oidc.body = body;

		const { params: authParams, middleware: tokenAuth } =
			getTokenAuth(provider);
		const { grantTypeParams } = instance(provider);

		for (const middleware of tokenAuth) {
			await middleware(ctx, () => {});
		}

		const grantParams = grantTypeParams.get(ctx.oidc.params.grant_type);
		if (grantParams) {
			Object.keys(ctx.oidc.params).forEach((key) => {
				if (!(authParams.has(key) || grantParams.has(key))) {
					delete ctx.oidc.params[key];
				}
			});
		}

		const supported = instance(provider).configuration.grantTypes;
		if (!supported.has(ctx.oidc.params.grant_type)) {
			throw new UnsupportedGrantType();
		}

		if (!ctx.oidc.client.grantTypeAllowed(ctx.oidc.params.grant_type)) {
			throw new InvalidRequest(
				'requested grant type is not allowed for this client'
			);
		}

		const grantType = ctx.oidc.params.grant_type;

		const { grantTypeHandlers } = instance(provider);
		const data = await grantTypeHandlers.get(grantType)(ctx);
		provider.emit('grant.success', ctx);

		return data;

		return [
			parseBody,
			paramsMiddleware.bind(undefined, grantTypeParams.get(undefined)),
			...tokenAuth,

			rejectDupes.bind(undefined, { only: grantTypeSet }),

			async function rejectDupesOptionalExcept(ctx, next) {
				const { grantTypeDupes } = instance(provider);
				const grantType = ctx.oidc.params.grant_type;
				if (grantTypeDupes.has(grantType)) {
					return rejectDupes(
						{ except: grantTypeDupes.get(grantType) },
						ctx,
						next
					);
				}
				return rejectDupes({}, ctx, next);
			},

			async function callTokenHandler(ctx) {}
		];
	},
	{
		body: t.Object({
			client_id: t.Optional(t.String()),
			client_assertion: t.Optional(t.String()),
			client_assertion_type: t.Optional(t.String()),
			client_secret: t.Optional(t.String()),
			code: t.Optional(t.String()),
			grant_type: t.String(),
			code_verifier: t.Optional(t.String()),
			redirect_uri: t.Optional(t.String())
		}),
		headers: t.Object({
			authorization: t.Optional(t.String())
		})
	}
);

export default function (provider) {}
