import { Elysia, t } from 'elysia';
import { eventBus } from 'lib/event_bus.js';
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
import { getUserStore, getBucketStore } from 'lib/adapters/index.js';
import { issueAndSend } from 'lib/verification/challenge.js';
import { Grant } from 'lib/models/grant.js';
import { Client } from 'lib/models/client.js';
import { responseModes } from 'lib/response_modes/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { resolveBucketForClient } from 'lib/admin/auth/resolveBucket.js';
import { buildConsentView, type PromptDetails } from './consentView.js';

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

	// An interaction that resolved with an error result aborts the authorization request and
	// redirects the User-Agent back to the client with that error (mirrors device_resume and the
	// authorization error handler).
	if (ctx.oidc.result?.error) {
		const { error, error_description: errorDescription } = ctx.oidc.result;
		const out = {
			error,
			...(errorDescription ? { error_description: errorDescription } : {}),
			...(ctx.oidc.params.state !== undefined
				? { state: ctx.oidc.params.state }
				: {}),
			iss: ISSUER
		};
		await setCookies();
		const mode = ctx.oidc.responseMode ?? 'query';
		const handler = responseModes.get(mode);
		return await handler({ oidc: ctx.oidc }, ctx.oidc.params.redirect_uri, out);
	}

	await checkClient(ctx.oidc);
	await checkResource(ctx.oidc);
	eventBus.emit('interaction.ended');
	assignClaims(ctx.oidc);
	await loadAccount(ctx.oidc);
	await loadGrant(ctx.oidc);
	const redirectUri = await interactions('resume', ctx.oidc);
	if (redirectUri) {
		await setCookies();
		return Response.redirect(redirectUri, 303);
	}
	await setCookies();
	return respond(ctx.oidc);
}

async function createGrant(interaction) {
	const grantId = interaction.payload.grantId;
	const details = (interaction.payload.prompt?.details ?? {}) as PromptDetails;
	const session = interaction.payload.session ?? {};
	const params = interaction.payload.params ?? {};

	let grant;
	if (grantId) {
		// modify the existing grant (reuses what the user already granted)
		grant = await Grant.find(grantId);
	} else {
		// establish a new grant for this account/client
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

	await grant.save();
	// record the consent outcome the resume pipeline (loadExistingGrant) reads back
	interaction.payload.result = {
		...(interaction.payload.result ?? {}),
		consent: { grantId: grant.id }
	};
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
		const interaction = await Interaction.find(params.uid, {
			error: new SessionNotFound('interaction session not found')
		});

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
			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			const bucketId = await resolveBucketForClient(clientId);
			const userStore = getUserStore(bucketId);
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
			if (!user.active) {
				return loginServer(uid, 'Invalid username or password');
			}
			const loginBucket = await getBucketStore().find(bucketId);
			if (loginBucket?.emailVerificationRequired && !user.verified) {
				return loginServer(
					uid,
					'Please verify your email before signing in. Check your inbox for the verification message.'
				);
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
		async ({ body, params: { uid }, interaction }) => {
			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			const bucketId = await resolveBucketForClient(clientId);
			const bucket = await getBucketStore().find(bucketId);

			// A closed bucket accepts no self-service sign-ups: no account, no email.
			if (bucket && !bucket.registrationOpen) {
				return new Response('Registration is closed for this application.', {
					status: 403
				});
			}

			if (body.password !== body.confirmPassword) {
				return new Response('Passwords do not match', { status: 400 });
			}

			const store = getUserStore(bucketId);
			const verificationRequired = bucket?.emailVerificationRequired ?? false;

			// Non-committal on an existing address: behave like the accepted path without
			// creating a duplicate or sending mail, so registration cannot be used to probe
			// which emails are registered.
			if (await store.findByEmail(body.email)) {
				return Response.redirect(`/ui/${uid}/login`, 303);
			}

			const user = await store.create(
				body.email,
				await Bun.password.hash(body.password),
				[],
				!verificationRequired
			);

			if (verificationRequired && bucket) {
				try {
					const { id, method } = await issueAndSend(user, bucket);
					if (method === 'code') {
						return Response.redirect(
							`/verify-email/code?ref=${encodeURIComponent(id)}`,
							303
						);
					}
					return Response.redirect(`/ui/${uid}/login?notice=verify`, 303);
				} catch {
					// Delivery failed: the account exists but is unverified; invite a retry.
					return new Response(
						'We could not send your verification email. Please try again later.',
						{ status: 502 }
					);
				}
			}

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
	.get('ui/:uid/consent', async ({ params: { uid }, interaction }) => {
		const params = interaction.payload.params as
			{ client_id?: string } | undefined;
		const clientId = params?.client_id;
		const client = clientId
			? ((await Client.tryFind(clientId)) as
					{ clientName?: string; client_name?: string } | undefined)
			: undefined;
		const clientName =
			client?.clientName || client?.client_name || clientId || uid;
		const details =
			(interaction.payload.prompt as { details?: PromptDetails } | undefined)
				?.details ?? {};
		const account = (
			interaction.payload.session as { accountId?: string } | undefined
		)?.accountId;
		return consentServer(
			buildConsentView({ uid, clientName, account, details })
		);
	})
	.post(
		'ui/:uid/consent',
		async ({ body, interaction, cookie }) => {
			if (body.action === 'allow') {
				await createGrant(interaction);
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
				ignoreSessionBinding: true,
				error: new NotFoundError()
			});

			if (code.isExpired) {
				throw new ExpiredError();
			} else if (code.payload.error || code.payload.accountId) {
				throw new AlreadyUsedError();
			}
			oidc.entity('DeviceCode', code);

			await checkClient(oidc);
			await checkResource(oidc);
			eventBus.emit('interaction.ended');
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
						? await DeviceCode.tryFind(interaction.payload.deviceCode, {
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
