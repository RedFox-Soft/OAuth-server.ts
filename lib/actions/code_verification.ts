import * as crypto from 'node:crypto';

import { Elysia, t } from 'elysia';

import sessionHandler from '../shared/session.ts';
import { InvalidClient, InvalidRequest } from '../helpers/errors.ts';
import { formPost } from '../html/formPost.js';
import { deviceInputPage, deviceConfirmPage } from '../html/device.js';
import { normalize, denormalize } from '../helpers/user_codes.ts';
import {
	ReRenderError,
	NoCodeError,
	NotFoundError,
	ExpiredError,
	AlreadyUsedError,
	AbortedError
} from '../helpers/re_render_errors.ts';
import { AuthorizationCookies, routeNames } from 'lib/consts/param_list.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import interactions from './authorization/interactions.js';
import loadGrant from './authorization/load_grant.js';
import loadAccount from './authorization/load_account.js';
import assignClaims from './authorization/assign_claims.js';
import checkResource from 'lib/shared/check_resource.js';
import checkClient from './authorization/check_client.js';
import deviceVerificationResponse from './authorization/device_user_flow_response.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Client } from 'lib/models/client.js';

// Renders (or re-renders) the user-code input page for an error. ReRenderErrors (bad/missing/
// expired/used code, aborted interaction) are ordinary re-renders and do NOT emit an error event;
// request/client errors DO emit `code_verification.error` and render at their own status.
function renderInputError(oidc, err) {
	const charset = ApplicationConfig['deviceFlow.charset'];
	const secret =
		oidc.session?.payload?.state?.secret ??
		crypto.randomBytes(24).toString('hex');
	const action = oidc.urlFor('code_verification');

	if (!(err instanceof ReRenderError)) {
		oidc.provider.emit('code_verification.error', err, oidc);
	}

	return deviceInputPage({ action, secret, charset, err });
}

export const codeVerification = new Elysia()
	.guard({
		cookie: AuthorizationCookies
	})
	.get(
		routeNames.code_verification,
		async ({ cookie, query }) => {
			const oidc = new OIDCContext(query);
			oidc.cookie = cookie;
			const setCookies = await sessionHandler(oidc);

			const charset = ApplicationConfig['deviceFlow.charset'];
			const secret = crypto.randomBytes(24).toString('hex');
			oidc.session.payload.state = { secret };

			const action = oidc.urlFor('code_verification');
			await setCookies();

			if (query.user_code) {
				return formPost(oidc, action, {
					xsrf: secret,
					user_code: query.user_code
				});
			}

			return deviceInputPage({ action, secret, charset });
		},
		{
			query: t.Object({
				user_code: t.Optional(t.String())
			})
		}
	)
	.post(
		routeNames.code_verification,
		async ({ cookie, body }) => {
			const oidc = new OIDCContext({});
			oidc.cookie = cookie;
			const setCookies = await sessionHandler(oidc);

			try {
				const { xsrf, user_code: userCode, confirm, abort } = body;

				if (!oidc.session.payload.state) {
					throw new InvalidRequest('could not find device form details');
				}
				if (oidc.session.payload.state.secret !== xsrf) {
					throw new InvalidRequest('xsrf token invalid');
				}

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
				if (
					code.payload.error ||
					code.payload.accountId ||
					code.payload.inFlight
				) {
					throw new AlreadyUsedError(userCode);
				}

				oidc.entity('DeviceCode', code);

				if (abort) {
					Object.assign(code.payload, {
						error: 'access_denied',
						errorDescription: 'End-User aborted interaction'
					});
					await code.save();
					throw new AbortedError();
				}

				if (!confirm) {
					const client = await Client.find(code.payload.clientId, {
						error: new InvalidClient('client is invalid', 'client not found')
					});
					oidc.entity('Client', client);

					const mask = ApplicationConfig['deviceFlow.mask'];
					const action = oidc.urlFor('code_verification');
					return deviceConfirmPage({
						action,
						secret: oidc.session.payload.state.secret,
						userCode: denormalize(normalized, mask),
						client
					});
				}

				code.payload.inFlight = true;
				await code.save();
				oidc.session.payload.state = undefined;

				// confirm === yes: resolve the interaction against the authenticated session and
				// either redirect to a required interaction (login/consent) or bind + render success.
				oidc.params = { ...code.payload.params };
				await checkClient(oidc);
				await checkResource(oidc);
				assignClaims(oidc);
				await loadAccount(oidc);
				await loadGrant(oidc);
				const destination = await interactions('device_resume', oidc);
				await setCookies();

				if (destination) {
					return Response.redirect(destination, 303);
				}

				return await deviceVerificationResponse(oidc);
			} catch (err) {
				return renderInputError(oidc, err);
			}
		},
		{
			body: t.Object({
				xsrf: t.Optional(t.String()),
				user_code: t.Optional(t.String()),
				confirm: t.Optional(t.String()),
				abort: t.Optional(t.String())
			})
		}
	);
