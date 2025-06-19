import * as crypto from 'node:crypto';

import sessionHandler from '../shared/session.ts';
import paramsMiddleware from '../shared/assemble_params.ts';
import instance from '../helpers/weak_cache.ts';
import { InvalidClient, InvalidRequest } from '../helpers/errors.ts';
import * as formHtml from '../helpers/user_code_form.ts';
import { formPost } from '../html/formPost.js';
import { normalize, denormalize } from '../helpers/user_codes.ts';
import {
	NoCodeError,
	NotFoundError,
	ExpiredError,
	AlreadyUsedError,
	AbortedError
} from '../helpers/re_render_errors.ts';
import { Elysia, t } from 'elysia';
import { AuthorizationCookies, routeNames } from 'lib/consts/param_list.js';
import interactions from './authorization/interactions.js';
import loadGrant from './authorization/load_grant.js';
import loadAccount from './authorization/load_account.js';
import assignClaims from './authorization/assign_claims.js';
import checkResource from 'lib/shared/check_resource.js';
import checkClient from './authorization/check_client.js';
import deviceUserFlowErrors from './authorization/device_user_flow_errors.js';
import deviceUserFlowResponse from './authorization/device_user_flow_response.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { DeviceCode } from 'lib/models/device_code.js';

async function codeVerificationActionHandler(ctx) {
	deviceUserFlowErrors;
	await checkClient(ctx);
	await checkResource(ctx);
	assignClaims(ctx);
	await loadAccount(ctx);
	await loadGrant(cxt);
	interactions('device_resume', ctx);
	await deviceUserFlowResponse(ctx);
}

export const codeVerification = new Elysia()
	.guard({
		cookies: AuthorizationCookies
	})
	.get(
		routeNames.code_verification,
		async ({ cookie, query }) => {
			const ctx = { cookie };
			ctx.oidc = new OIDCContext(ctx);

			const setCookies = await sessionHandler();
		},
		{
			query: t.Object({
				user_code: t.Optional(t.String())
			})
		}
	);

export const get = [
	paramsMiddleware.bind(undefined, new Set(['user_code'])),
	async function renderCodeVerification(ctx) {
		const { charset, userCodeInputSource } = instance(ctx.oidc.provider)
			.features.deviceFlow;

		// TODO: generic xsrf middleware to remove this
		const secret = crypto.randomBytes(24).toString('hex');
		ctx.oidc.session.state = { secret };

		const action = ctx.oidc.urlFor('code_verification');
		if (ctx.oidc.params.user_code) {
			formPost(ctx, action, {
				xsrf: secret,
				user_code: ctx.oidc.params.user_code
			});
		} else {
			await userCodeInputSource(
				ctx,
				formHtml.input(action, secret, undefined, charset)
			);
		}
	}
];

export const post = [
	paramsMiddleware.bind(
		undefined,
		new Set(['xsrf', 'user_code', 'confirm', 'abort'])
	),

	async function codeVerificationCSRF(ctx, next) {
		if (!ctx.oidc.session.state) {
			throw new InvalidRequest('could not find device form details');
		}
		if (ctx.oidc.session.state.secret !== ctx.oidc.params.xsrf) {
			throw new InvalidRequest('xsrf token invalid');
		}
		await next();
	},

	async function loadDeviceCodeByUserInput(ctx, next) {
		const { userCodeConfirmSource, mask } = instance(ctx.oidc.provider).features
			.deviceFlow;
		const { user_code: userCode, confirm, abort } = ctx.oidc.params;

		if (!userCode) {
			throw new NoCodeError();
		}

		const normalized = normalize(userCode);
		const code = await DeviceCode.findByUserCode(normalized, {
			ignoreExpiration: true
		});

		if (!code) {
			throw new NotFoundError(userCode);
		}

		if (code.isExpired) {
			throw new ExpiredError(userCode);
		}

		if (code.error || code.accountId || code.inFlight) {
			throw new AlreadyUsedError(userCode);
		}

		ctx.oidc.entity('DeviceCode', code);

		if (abort) {
			Object.assign(code, {
				error: 'access_denied',
				errorDescription: 'End-User aborted interaction'
			});

			await code.save();
			throw new AbortedError();
		}

		if (!confirm) {
			const client = await ctx.oidc.provider.Client.find(code.clientId);
			if (!client) {
				throw new InvalidClient('client is invalid', 'client not found');
			}
			ctx.oidc.entity('Client', client);

			const action = ctx.oidc.urlFor('code_verification');
			await userCodeConfirmSource(
				ctx,
				formHtml.confirm(action, ctx.oidc.session.state.secret, userCode),
				client,
				code.deviceInfo,
				denormalize(normalized, mask)
			);
			return;
		}

		code.inFlight = true;
		await code.save();

		await next();
	},

	function cleanup(ctx, next) {
		ctx.oidc.session.state = undefined;
		return next();
	}
];
