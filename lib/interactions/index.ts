import { Elysia, t } from 'elysia';
import { provider } from 'lib/provider.js';
import { loginServer } from './loginServer.tsx';
import { SessionNotFound } from 'lib/helpers/errors.js';
import epochTime from '../helpers/epoch_time.ts';
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

const htmlTeamplate = Bun.file('./lib/interactions/htmlTeamplate.html');

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
		const interaction = await provider.Interaction.find(params.uid);
		if (!interaction) {
			throw new SessionNotFound('interaction session not found');
		}

		if (interaction.session?.uid) {
			const session = await provider.Session.findByUid(interaction.session.uid);
			if (!session) {
				throw new SessionNotFound('session not found');
			}
			if (interaction.session.accountId !== session.accountId) {
				throw new SessionNotFound('session principal changed');
			}
		}

		return { interaction };
	})
	.get('ui/:uid/login', async ({ params: { uid } }) => {
		let html = await htmlTeamplate.text();
		html = html
			.replace('<!--app-title-->', 'Login Page')
			.replace('<!--app-html-->', loginServer(uid));
		return new Response(html, {
			headers: {
				'Content-Type': 'text/html; charset=utf-8'
			}
		});
	})
	.get('ui/:uid/abort', async ({ interaction }) => {
		interaction.result = {
			error: 'access_denied',
			error_description: 'End-User aborted interaction'
		};
		await interaction.save(interaction.exp - epochTime());

		return Response.redirect(interaction.returnTo, 303);
	})
	.get('ui/:uid/resume', async ({ interaction, cookie }) => {
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
	})
	.get('ui/:uid/device_resume', async ({ interaction, cookie }) => {
		const ctx = { cookie, _matchedRouteName: 'ui.device_resume' };
		ctx.oidc = new OIDCContext(ctx);

		const setCookies = await sessionHandler(ctx);

		deviceUserFlowErrors;
		await getResume(ctx, interaction);
		cookie._interaction.remove();

		const code = await ctx.oidc.provider.DeviceCode.find(
			interaction.deviceCode,
			{ ignoreExpiration: true, ignoreSessionBinding: true }
		);

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
