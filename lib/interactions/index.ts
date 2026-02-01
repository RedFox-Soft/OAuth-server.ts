import { Elysia, t } from 'elysia';
import { provider } from 'lib/provider.js';
import {
	consentServer,
	loginServer,
	registrationServer
} from './serverRender.js';
import { SessionNotFound } from 'lib/helpers/errors.js';
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
	NotFoundError
} from 'lib/helpers/re_render_errors.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Session } from 'lib/models/session.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Interaction } from 'lib/models/interaction.js';
import { getUserStore } from 'lib/adapters/index.js';
import { Grant } from 'lib/models/grant.js';

async function resume(interaction, cookie) {
	const ctx = { cookie, _matchedRouteName: 'ui.resume' };
	ctx.oidc = new OIDCContext(ctx);

	const setCookies = await sessionHandler(ctx);
	await getResume(ctx, interaction);
	cookie._interaction.remove();
	await checkClient(ctx);
	await checkResource(ctx);
	provider.emit('interaction.ended');
	assignClaims(ctx);
	await loadAccount(ctx);
	await loadGrant(ctx);
	await interactions('resume', ctx);
	await setCookies();
	return respond(ctx);
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
	const result = { consent: { grantId: await grant.save() } };
	await provider.interactionFinished(ctx.req, ctx.res, result, {
		mergeWithLastSubmission: true
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

		if (interaction.session?.uid) {
			const session = await Session.findByUid(interaction.session.uid);
			if (!session) {
				throw new SessionNotFound('session not found');
			}
			if (interaction.session.accountId !== session.accountId) {
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
			interaction.result = {
				login: {
					accountId: user.sub
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
	.get('ui/:uid/abort', async ({ interaction }) => {
		interaction.result = {
			error: 'access_denied',
			error_description: 'End-User aborted interaction'
		};
		await interaction.save(interaction.exp - epochTime());

		return Response.redirect(interaction.returnTo, 303);
	})
	.get('ui/:uid/device_resume', async ({ interaction, cookie }) => {
		const ctx = { cookie, _matchedRouteName: 'ui.device_resume' };
		ctx.oidc = new OIDCContext(ctx);

		const setCookies = await sessionHandler(ctx);

		deviceUserFlowErrors;
		await getResume(ctx, interaction);
		cookie._interaction.remove();

		const code = await DeviceCode.find(interaction.deviceCode, {
			ignoreExpiration: true,
			ignoreSessionBinding: true
		});

		if (!code) {
			throw new NotFoundError();
		} else if (code.isExpired) {
			throw new ExpiredError();
		} else if (code.error || code.accountId) {
			throw new AlreadyUsedError();
		}
		ctx.oidc.entity('DeviceCode', code);

		await checkClient(ctx);
		await checkResource(ctx);
		provider.emit('interaction.ended');
		assignClaims(ctx);
		await loadAccount(ctx);
		await loadGrant(ctx);
		await interactions('device_resume', ctx);
		await setCookies();
		deviceUserFlowResponse;
	});
