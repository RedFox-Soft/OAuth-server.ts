import { Elysia, t } from 'elysia';
import { provider } from 'lib/provider.js';
import {
	consentServer,
	loginServer,
	registrationServer
} from './serverRender.js';
import { AccessDenied, SessionNotFound } from 'lib/helpers/errors.js';
import epochTime from '../helpers/epoch_time.js';
import sessionHandler from 'lib/shared/session.js';
import respond from 'lib/actions/authorization/respond.js';
import getResume from 'lib/actions/authorization/resume.js';
import checkClient from 'lib/actions/authorization/check_client.js';
import checkResource from 'lib/shared/check_resource.js';
import assignClaims from 'lib/actions/authorization/assign_claims.js';
import loadAccount from 'lib/actions/authorization/load_account.js';
import loadGrant from 'lib/actions/authorization/load_grant.js';
import interactions from 'lib/actions/authorization/interactions.js';
import {
	AlreadyUsedError,
	ExpiredError,
	NotFoundError,
	AbortedError,
	ReRenderError
} from 'lib/helpers/re_render_errors.js';
import { deviceInputPage } from 'lib/html/device.js';
import deviceVerificationResponse from 'lib/actions/authorization/device_user_flow_response.js';
import * as crypto from 'node:crypto';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Session } from 'lib/models/session.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Interaction } from 'lib/models/interaction.js';
import { getUserStore } from 'lib/adapters/index.js';
import { Grant } from 'lib/models/grant.js';

async function resume(interaction, cookie) {
	const ctx = { cookie, _matchedRouteName: 'ui.resume' };
	ctx.oidc = new OIDCContext({}, {}, 'ui.resume');
	ctx.oidc.cookie = cookie;

	const setCookies = await sessionHandler(ctx.oidc);
	const confirmPage = await getResume(ctx.oidc, interaction);
	if (confirmPage) {
		return confirmPage;
	}
	cookie._interaction.remove();
	await checkClient(ctx.oidc);
	await checkResource(ctx.oidc);
	provider.emit('interaction.ended');
	assignClaims(ctx.oidc);
	await loadAccount(ctx.oidc);
	await loadGrant(ctx.oidc);
	await interactions('resume', ctx.oidc);
	await setCookies();
	return respond(ctx.oidc);
}

async function createGrant(interaction) {
	const { grantId } = interaction;
	let grant;
	if (grantId) {
		// we'll be modifying existing grant in existing session
		grant = await Grant.find(grantId);
	} else {
		// we're establishing a new grant
		grant = new Grant({
			accountId: session.accountId,
			clientId: params.client_id
		});
	}

	if (details.missingOIDCScope) {
		grant.addOIDCScope(details.missingOIDCScope.join(' '));
	}
	if (details.missingOIDCClaims) {
		grant.addOIDCClaims(details.missingOIDCClaims);
	}
	if (details.missingResourceScopes) {
		for (const [indicator, scope] of Object.entries(
			details.missingResourceScopes
		)) {
			grant.addResourceScope(indicator, scope.join(' '));
		}
	}
	Object.assign(interaction.result, {
		consent: { grantId: await grant.save() }
	});
}

export const ui = new Elysia()
	.guard({
		params: t.Object({
			uid: t.String()
		}),
		cookie: t.Cookie({
			_interaction: t.String({
				error: 'Invalid interaction cookie'
			})
		})
	})
	.resolve(async ({ cookie, params }) => {
		const cookieId = cookie._interaction.value;
		const interaction = await Interaction.find(params.uid);
		if (!interaction) {
			throw new SessionNotFound('interaction session not found');
		}

		if (interaction.payload.session?.uid) {
			const session = await Session.findByUid(interaction.payload.session.uid);
			if (!session) {
				throw new SessionNotFound('session not found');
			}
			if (interaction.payload.session.accountId !== session.payload.accountId) {
				throw new SessionNotFound('session principal changed');
			}
		}

		return { interaction };
	})
	.get('ui/:uid/login', async ({ params: { uid } }) => loginServer(uid))
	.post(
		'ui/:uid/login',
		async ({ body, params: { uid }, interaction, cookie }) => {
			const userStore = getUserStore();
			const user = await userStore.findByEmail(body.username);
			if (!user) {
				return loginServer(uid, 'Invalid username or password');
			}
			const validPassword = await Bun.password.verify(
				body.password,
				user.password
			);
			if (!validPassword) {
				return loginServer(uid, 'Invalid username or password');
			}
			interaction.payload.result = {
				login: {
					accountId: user._id,
					transient: body.remember === 'on'
				}
			};
			return resume(interaction, cookie);
		},
		{
			body: t.Object({
				username: t.String(),
				password: t.String(),
				remember: t.Optional(t.Literal('on'))
			})
		}
	)
	.get('ui/:uid/registration', async ({ params: { uid } }) =>
		registrationServer(uid)
	)
	.post(
		'ui/:uid/registration',
		async ({ body, params: { uid } }) => {
			if (body.password !== body.confirmPassword) {
				return new Response('Passwords do not match', { status: 400 });
			}
			await getUserStore().create(
				body.email,
				await Bun.password.hash(body.password)
			);
			return Response.redirect(`/ui/${uid}/login`, 303);
		},
		{
			body: t.Object({
				email: t.String(),
				password: t.String(),
				confirmPassword: t.String()
			})
		}
	)
	.get('ui/:uid/consent', async ({ params: { uid } }) => consentServer(uid))
	.post(
		'ui/:uid/consent',
		async ({ body, interaction, cookie }) => {
			if (body.action === 'allow') {
				return resume(interaction, cookie);
			}

			throw new AccessDenied('End-User denied consent');
		},
		{
			body: t.Object({
				action: t.Union([t.Literal('allow'), t.Literal('cancel')])
			})
		}
	)
	.get('ui/:uid/resume', async ({ interaction, cookie }) =>
		resume(interaction, cookie)
	)
	.get('ui/:uid/device_resume', async ({ interaction, cookie }) => {
		const oidc = new OIDCContext({}, {}, 'ui.device_resume');
		oidc.cookie = cookie;

		const setCookies = await sessionHandler(oidc);
		const action = oidc.urlFor('code_verification');
		let code;

		try {
			const confirmPage = await getResume(oidc, interaction);
			if (confirmPage) {
				// subject changed — logout confirmation self-submitting form
				return confirmPage;
			}

			if (oidc.result?.error) {
				throw new AccessDenied(undefined, oidc.result.error_description);
			}

			cookie._interaction.remove();

			code = await DeviceCode.find(interaction.payload.deviceCode, {
				ignoreExpiration: true,
				ignoreSessionBinding: true
			});

			if (!code) {
				throw new NotFoundError();
			} else if (code.isExpired) {
				throw new ExpiredError();
			} else if (code.payload.error || code.payload.accountId) {
				throw new AlreadyUsedError();
			}
			oidc.entity('DeviceCode', code);

			await checkClient(oidc);
			await checkResource(oidc);
			provider.emit('interaction.ended');
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
			let renderErr = err;

			if (!(err instanceof ReRenderError)) {
				const errored =
					code ||
					(interaction.payload.deviceCode
						? await DeviceCode.find(interaction.payload.deviceCode, {
								ignoreExpiration: true,
								ignoreSessionBinding: true
							})
						: undefined);
				if (errored && err instanceof AccessDenied) {
					Object.assign(errored.payload, {
						error: 'access_denied',
						errorDescription:
							err.error_description ?? 'End-User aborted interaction'
					});
					await errored.save();
					renderErr = new AbortedError();
				}
			}

			const secret = crypto.randomBytes(24).toString('hex');
			return deviceInputPage({ action, secret, err: renderErr });
		}
	});
