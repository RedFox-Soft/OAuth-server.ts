// Aliased: this module already imports a `NotFoundError` from helpers/re_render_errors.js, which is the
// device-flow re-render error and a different thing entirely. Elysia's is the one that produces the same
// answer the server gives for a path it does not serve, which is what an unknown provider must look like.
import { Elysia, NotFoundError as UnservedPath, t } from 'elysia';
import { eventBus } from 'lib/event_bus.js';
import { DiscoveryError, discover } from 'lib/federation/discovery.js';
import { authorizationUrl, supportsPkce } from 'lib/federation/flow.js';
import { findEnabledProvider } from 'lib/federation/providers.js';
import { consumeHandoff, openPending } from 'lib/federation/state.js';
import {
	federationExpiredPage,
	federationInactivePage,
	federationUpstreamPage,
	passwordLoginClosedPage
} from 'lib/federation/pages.js';
import { loginOptionsForClient } from './loginOptions.js';
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
import { request as requestPasswordReset } from 'lib/password_reset/challenge.js';
import {
	resetRequestPage,
	resetRequestAcceptedPage,
	resetRateLimitedPage
} from './resetPages.js';
import { Grant } from 'lib/models/grant.js';
import { Client } from 'lib/models/client.js';
import { responseModes } from 'lib/response_modes/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { resolveBucketForClient } from 'lib/admin/auth/resolveBucket.js';
import { buildConsentView, type PromptDetails } from './consentView.js';
import { NOTICE_VERIFY, resolveNotice } from './notices.js';
import {
	registrationClosedPage,
	registrationSendFailedPage
} from './registrationPages.js';
import { buildUILoginPath } from './buildUIPath.js';
import { ApplicationConfig } from 'lib/configs/application.js';

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
	const redirectUri = await interactions(ctx.oidc);
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

	/*
	 * `tryFind`, because the interaction's grantId is a hint and not proof that a grant was stored. The
	 * Interaction constructor copies the id off whatever Grant instance the authorization pipeline put
	 * in the context (lib/models/interaction.ts), and `loadGrant` puts an *unsaved* one there whenever
	 * the account has no grant for this client yet — nothing persists it until the line below. So on a
	 * first consent the id names nothing, and `find` would raise its notFoundError at the instant the
	 * user clicks approve. base_model declares that error as InvalidToken, so the refusal read
	 * `401 invalid token provided` — a message about credentials for what is actually a missing record,
	 * on a request that carries no token at all.
	 *
	 * A grantId that resolves to nothing is the same state as no grantId: there is no prior consent to
	 * extend, so a new grant is established and its id is what the resume pipeline reads back below.
	 */
	const stored = grantId ? await Grant.tryFind(grantId) : undefined;
	const grant =
		stored ??
		// establish a new grant for this account/client
		new Grant({
			accountId: session.accountId,
			clientId: params.client_id
		});

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
	// The arm whose absence kept grant.rar permanently empty, and with it the shaping seams' principal
	// input. `details.rar` is the not-yet-granted subset, so this plus what the grant already held is
	// every requested detail.
	if (details.rar) {
		for (const detail of details.rar) {
			grant.addRar(detail);
		}
	}

	await grant.save();
	// record the consent outcome the resume pipeline (loadExistingGrant) reads back
	interaction.payload.result = {
		...(interaction.payload.result ?? {}),
		consent: { grantId: grant.id }
	};
}

/*
 * The password-only doors of a federated-only bucket.
 *
 * Returned as a page rather than checked inline at five call sites, so "closed means closed everywhere" is
 * one function. Each caller invokes it **before** any other check — including registration's deliberately
 * non-committal handling of an address that already exists: with the door shut there is nothing to be
 * non-committal about, and the refusal reveals a bucket setting rather than anything about an account.
 */
async function passwordDoorClosed(
	clientId: string | undefined,
	uid: string
): Promise<Response | undefined> {
	const bucket = await getBucketStore().find(
		await resolveBucketForClient(clientId)
	);
	// `=== false` exactly: absent means available, which is what a bucket predating the field must get.
	return bucket?.passwordLogin === false
		? passwordLoginClosedPage(uid)
		: undefined;
}

/* The client that began an interaction — the only trustworthy route to a bucket. */
function clientIdOf(interaction: {
	payload: { params?: unknown };
}): string | undefined {
	return (interaction.payload.params as { client_id?: string } | undefined)
		?.client_id;
}

/*
 * Where the pending authorization request hands off once this interaction resolves. Every page rendered
 * inside an interaction needs it: the browser checks that address against the policy of the document
 * whose form was submitted, because the submission's redirect chain ends there — see lib/html/csp.ts.
 */
function redirectUriOf(interaction: {
	payload: { params?: unknown };
}): string | undefined {
	return (interaction.payload.params as { redirect_uri?: string } | undefined)
		?.redirect_uri;
}

export const ui = new Elysia()
	.guard({
		params: t.Object({
			uid: t.String(),
			/*
			 * Declared on the shared guard, not merely on the one route that has it in its path, because the
			 * app runs `normalize: false`: an undeclared path parameter is *refused* rather than stripped, and
			 * the guard's schema is merged with the route's rather than replaced by it. A route-level
			 * declaration alone answers 422 with "Property 'providerId' should not be provided" and never
			 * reaches the handler — measured (specs/022-oidc-federation-login/research.md D2).
			 *
			 * Optional, so the routes that do not take one are unaffected: a request can only carry it if its
			 * matched path declares it.
			 */
			providerId: t.Optional(t.String())
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
	/*
	 * `notice` is typed as an optional string rather than a literal union on purpose: a value the server
	 * did not mint must render the ordinary login page, and a union would answer 422 instead — which is
	 * what a stale bookmark or an old email link would hit.
	 */
	.get(
		'ui/:uid/login',
		async ({ params: { uid }, query, interaction }) => {
			/*
			 * The bucket is resolved on the GET as well as the POST, exactly as the registration route already
			 * does: what this page offers — a password form, provider buttons, or only the latter — is a
			 * property of the bucket, and a page that offered what the POST would refuse is a dead end dressed
			 * as an invitation.
			 */
			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			return loginServer(uid, {
				notice: resolveNotice(query.notice),
				handOffTo: redirectUriOf(interaction),
				...(await loginOptionsForClient(clientId))
			});
		},
		{ query: t.Object({ notice: t.Optional(t.String()) }) }
	)
	.post(
		'ui/:uid/login',
		async ({ body, params: { uid }, interaction, cookie }) => {
			const clientId = clientIdOf(interaction);
			// Before the lookup, so this cannot be used to probe which addresses exist.
			const closed = await passwordDoorClosed(clientId, uid);
			if (closed) return closed;

			const bucketId = await resolveBucketForClient(clientId);
			const userStore = getUserStore(bucketId);
			const user = await userStore.findByEmail(body.username);
			if (!user) {
				return loginServer(uid, {
					errorMessage: 'Invalid username or password',
					handOffTo: redirectUriOf(interaction)
				});
			}
			const validPassword = await Bun.password.verify(
				body.password,
				user.password
			);
			if (!validPassword) {
				return loginServer(uid, {
					errorMessage: 'Invalid username or password',
					handOffTo: redirectUriOf(interaction)
				});
			}
			if (!user.active) {
				return loginServer(uid, {
					errorMessage: 'Invalid username or password',
					handOffTo: redirectUriOf(interaction)
				});
			}
			const loginBucket = await getBucketStore().find(bucketId);
			if (loginBucket?.emailVerificationRequired && !user.verified) {
				return loginServer(uid, {
					errorMessage:
						'Please verify your email before signing in. Check your inbox for the verification message.',
					handOffTo: redirectUriOf(interaction)
				});
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
	/*
	 * Leg one of a federated sign-in. Declares its own `params` schema, and that is load-bearing rather than
	 * tidy: the guard above declares only `uid`, and a two-parameter route under it answers **422 without
	 * ever reaching the handler** — measured, not assumed (specs/022-oidc-federation-login/research.md D2).
	 * The same family as Elysia's query handling on the audit route: a declared schema on a request parameter
	 * describes what the framework will do with the value, and an undeclared one is not merely ignored.
	 */
	.get(
		'ui/:uid/federation/:providerId/start',
		async ({ params: { uid, providerId }, interaction }) => {
			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			// The bucket comes from the client that began the interaction, never from the request: a bucket
			// taken from a parameter would let anyone aim this at any tenant's provider.
			const bucketId = await resolveBucketForClient(clientId);
			const bucket = await getBucketStore().find(bucketId);
			/*
			 * `providerId` is optional in the merged params type because the shared guard declares it that way
			 * (it has to — see the guard). This path always supplies it, so the check is narrowing rather than
			 * logic; asserting instead would be claiming a guarantee the type does not carry, and answering as
			 * unserved is the correct response either way.
			 */
			const provider = providerId
				? findEnabledProvider(bucket, providerId)
				: undefined;

			// Unknown, disabled, or another bucket's — answered as unserved, so a probe learns nothing about
			// which providers a bucket holds.
			if (!provider) {
				throw new UnservedPath();
			}

			let metadata;
			try {
				metadata = await discover(provider.issuer);
			} catch (err) {
				if (err instanceof DiscoveryError) {
					eventBus.emit('federation.upstream.error', {
						providerId: provider.id,
						reason: err.reason
					});
					return federationUpstreamPage();
				}
				throw err;
			}

			const secrets = await openPending({
				interactionUid: uid,
				bucketId,
				providerId: provider.id,
				withPkce: supportsPkce(metadata)
			});

			return Response.redirect(
				authorizationUrl(provider, metadata, secrets),
				303
			);
		},
		{ params: t.Object({ uid: t.String(), providerId: t.String() }) }
	)
	/*
	 * Leg three: back inside the interaction, where the strict cookie applies again because leg two
	 * redirected same-site. From here on the flow is identical to a password sign-in by construction — the
	 * same `result.login` and the same `resume()`.
	 */
	.get(
		'ui/:uid/federation/complete',
		async ({ params: { uid }, query, interaction, cookie }) => {
			const handoff = await consumeHandoff(query.ref, uid);
			if (!handoff?.accountId) {
				return federationExpiredPage();
			}

			const clientId = (
				interaction.payload.params as { client_id?: string } | undefined
			)?.client_id;
			const bucketId = await resolveBucketForClient(clientId);
			const user = await getUserStore(bucketId).find(handoff.accountId);
			// Re-read rather than trusted from the record: an account frozen between hops must not sign in.
			if (!user || !user.active) {
				return federationInactivePage();
			}

			const bucket = await getBucketStore().find(bucketId);
			if (bucket?.emailVerificationRequired && !user.verified) {
				/*
				 * The same refusal a password sign-in meets, reusing the same challenge and the same notice
				 * spec 021 made real. A second verification flow would be two answers to a settled question.
				 */
				try {
					const { id, method } = await issueAndSend(user, bucket);
					if (method === 'code') {
						return Response.redirect(
							`/verify-email/code?ref=${encodeURIComponent(id)}`,
							303
						);
					}
				} catch {
					return federationUpstreamPage();
				}
				return Response.redirect(buildUILoginPath(uid, NOTICE_VERIFY), 303);
			}

			interaction.payload.result = {
				// No `transient`: there is no "remember me" on a federated sign-in.
				login: { accountId: user._id }
			};
			return resume(interaction, cookie);
		},
		{
			params: t.Object({ uid: t.String() }),
			query: t.Object({ ref: t.String() })
		}
	)
	.get('ui/:uid/forgot-password', async ({ params: { uid }, interaction }) => {
		const closed = await passwordDoorClosed(clientIdOf(interaction), uid);
		// There is no password to reset, so offering the form would be a dead end dressed as help.
		return closed ?? resetRequestPage(uid);
	})
	.post(
		'ui/:uid/forgot-password',
		async ({ body, params: { uid }, interaction }) => {
			const clientId = clientIdOf(interaction);
			const closed = await passwordDoorClosed(clientId, uid);
			if (closed) return closed;

			/*
			 * The bucket comes from the client that started this interaction, never from the request. A
			 * `client_id` taken from the form would let anyone aim the lookup at any bucket, which turns a
			 * reset form into a cross-bucket address prober.
			 */
			const bucketId = await resolveBucketForClient(clientId);
			const outcome = await requestPasswordReset(body.email, bucketId);

			if (!outcome.ok) {
				return resetRateLimitedPage(
					outcome.reason === 'cooldown'
						? 'Please wait a moment before requesting another reset email.'
						: 'You have requested too many reset emails today. Please try again later.'
				);
			}

			// One page for every accepted outcome — sent or not. A response that varied would answer "does
			// this address have an account here?" for anyone who asked.
			return resetRequestAcceptedPage();
		},
		{
			body: t.Object({
				email: t.String()
			})
		}
	)
	/*
	 * The bucket is resolved on the GET as well as the POST: a form that can only be refused on
	 * submission is a dead end dressed as an invitation, and the two extra reads are point lookups.
	 */
	.get('ui/:uid/registration', async ({ params: { uid }, interaction }) => {
		const clientId = clientIdOf(interaction);
		const closed = await passwordDoorClosed(clientId, uid);
		if (closed) return closed;

		const bucket = await getBucketStore().find(
			await resolveBucketForClient(clientId)
		);
		if (bucket && !bucket.registrationOpen) {
			return registrationClosedPage();
		}
		return registrationServer(uid, { handOffTo: redirectUriOf(interaction) });
	})
	.post(
		'ui/:uid/registration',
		async ({ body, params: { uid }, interaction }) => {
			const clientId = clientIdOf(interaction);
			// Ahead of the non-committal existing-address handling below, deliberately.
			const closed = await passwordDoorClosed(clientId, uid);
			if (closed) return closed;

			const bucketId = await resolveBucketForClient(clientId);
			const bucket = await getBucketStore().find(bucketId);

			// A closed bucket accepts no self-service sign-ups: no account, no email.
			if (bucket && !bucket.registrationOpen) {
				return registrationClosedPage();
			}

			// The user's own form comes back with their address still in it. Neither password is echoed,
			// into the markup or the props.
			if (body.password !== body.confirmPassword) {
				return registrationServer(uid, {
					errorMessage: 'Passwords do not match',
					email: body.email,
					handOffTo: redirectUriOf(interaction)
				});
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
					return Response.redirect(buildUILoginPath(uid, NOTICE_VERIFY), 303);
				} catch {
					// Delivery failed: the account exists but is unverified; invite a retry.
					return registrationSendFailedPage();
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
		// The view builder reads no configuration, so the type → label map is resolved here and
		// handed in.
		const rarLabels = Object.fromEntries(
			Object.entries(
				ApplicationConfig['richAuthorizationRequests.types'] ?? {}
			).map(([type, descriptor]) => [
				type,
				(descriptor as { label?: string })?.label ?? type
			])
		);
		return consentServer(
			buildConsentView({ uid, clientName, account, details, rarLabels }),
			{ handOffTo: redirectUriOf(interaction) }
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
			const destination = await interactions(oidc);
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
