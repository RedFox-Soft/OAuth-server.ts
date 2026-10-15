import { hostOfRequest } from 'lib/consts/request_host.js';
import { AMR_FOR_DISTINCTION } from 'lib/consts/amr.js';
import { END_USER_PASSWORD_MIN_LENGTH } from 'lib/consts/password_policy.js';
import {
	bucketAtHost,
	bucketIsScheduled,
	isCanonicalHost
} from 'lib/admin/auth/bucketAddress.js';
// Aliased: this module already imports a `NotFoundError` from helpers/re_render_errors.js, which is the
// device-flow re-render error and a different thing entirely. Elysia's is the one that produces the same
// answer the server gives for a path it does not serve, which is what an unknown provider must look like.
import { Elysia, NotFoundError as UnservedPath, t } from 'elysia';
import { PageResponses } from 'lib/shared/response_schemas.js';
import { eventBus } from 'lib/event_bus.js';
import { DiscoveryError } from 'lib/federation/discovery.js';
import { upstreamMetadata } from 'lib/federation/upstream.js';
import { authorizationUrl, supportsPkce } from 'lib/federation/flow.js';
import { findEnabledProvider } from 'lib/federation/providers.js';
import { consumeHandoff, openPending } from 'lib/federation/state.js';
import { settlePendingLink } from 'lib/federation/pending_link.js';
import {
	federationExpiredPage,
	federationInactivePage,
	federationUpstreamPage,
	passwordLoginClosedPage
} from 'lib/federation/pages.js';
import {
	loginOptionsForBucket,
	loginOptionsForClient,
	type LoginOptions
} from './loginOptions.js';
import {
	clearFailures,
	isThrottled,
	recordAttempt
} from '../login_throttle/throttle.js';
import {
	consentServer,
	loginServer,
	registrationServer,
	totpServer
} from './serverRender.js';
import { verifyForAccount } from 'lib/totp/verify.js';
import {
	confirm as confirmEnrollment,
	offer as offerEnrollment
} from 'lib/totp/enrollment.js';
import { MAX_ATTEMPTS_PER_INTERACTION } from 'lib/totp/consts.js';
import {
	CustomOIDCProviderError,
	errorForCode,
	InvalidClient,
	InvalidRedirectUri,
	InvalidRequest,
	SessionNotFound
} from 'lib/helpers/errors.js';
import {
	deliverAuthorizationError,
	getObjFromError,
	refusesRedirect,
	type DeliveryCapture
} from 'lib/shared/authorization_error_delivery.js';
import { captureFault } from 'lib/error_store/capture.js';
import sessionHandler from 'lib/shared/session.js';
import respond from 'lib/actions/authorization/respond.js';
import getResume from 'lib/actions/authorization/resume.js';
import checkClient from 'lib/actions/authorization/check_client.js';
import checkResource from 'lib/shared/check_resource.js';
import assignClaims from 'lib/actions/authorization/assign_claims.js';
import loadAccount from 'lib/actions/authorization/load_account.js';
import { canSignIn } from 'lib/end_users/can_sign_in.js';
import loadGrant from 'lib/actions/authorization/load_grant.js';
import interactions, {
	expiredInteractionCookie
} from 'lib/actions/authorization/interactions.js';
import {
	endUserCookieAttributes,
	type PipelineParams
} from 'lib/consts/param_list.js';
import presence from 'lib/helpers/validate_presence.js';
import constantEquals from 'lib/helpers/constant_equals.js';
import {
	AlreadyUsedError,
	ExpiredError,
	NotFoundError,
	AbortedError,
	ReRenderError,
	UnfinishedError
} from 'lib/helpers/re_render_errors.js';
import { deviceInputPage } from 'lib/html/device.js';
import deviceVerificationResponse from 'lib/actions/authorization/device_user_flow_response.js';
import * as crypto from 'node:crypto';
import { issuingBucket } from 'lib/admin/auth/bucketAddress.js';
import { OIDCContext, type OIDCCookies } from 'lib/helpers/oidc_context.js';
import { Session } from 'lib/models/session.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Interaction } from 'lib/models/interaction.js';
import { getUserStore, getBucketStore } from 'lib/adapters/index.js';
import {
	DuplicateEndUserError,
	type User,
	type UserBucket
} from 'lib/adapters/types.js';
import { issueAndSend, sendOnDemand } from 'lib/verification/challenge.js';
import { request as requestPasswordReset } from 'lib/password_reset/challenge.js';
import { resetRequestPage, resetRequestAcceptedPage } from './resetPages.js';
import { Grant } from 'lib/models/grant.js';
import { Client, redirectUriAllowed } from 'lib/models/client.js';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.js';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.js';
import { registeredAdministrator } from 'lib/admin/administrators.js';
import {
	buildConsentView,
	type ConsentView,
	type DeclaredResourceFacts,
	type GrantedSoFar,
	type PromptDetails
} from './consentView.js';
import {
	consentChoices,
	type ConsentChoices,
	type SelectableItem
} from './consentChoices.js';
import { adapter } from 'lib/adapters/index.js';
import { clientProvenance, grantTypeAllowed } from 'lib/models/client.js';
import { readLogo } from 'lib/models/client/logo.js';
import { profileClaims } from 'lib/consts/profile_claims.js';
import { hasOwnOrigin, issuerFor } from 'lib/configs/issuer.js';
import { ttl } from 'lib/configs/liveTime.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { denormalize } from 'lib/helpers/user_codes.js';
import { versionedAsset } from 'lib/html/versionedAsset.js';
import { accountPageUrl } from 'lib/account_page/client.js';
import { findDeclaredResource } from 'lib/resources/registry.js';
import { namespaceOf } from 'lib/resources/namespace.js';
import { isMcpResource } from 'lib/mcp/resource_server.js';
import { isLoopbackRedirect } from 'lib/client_metadata_document/identifier.js';
import {
	NOTICE_FEDERATION_LINK,
	NOTICE_VERIFY,
	NOTICE_VERIFY_RECENT,
	NOTICE_VERIFY_RESENT,
	NOTICE_VERIFY_UNSENT,
	resolveNotice
} from './notices.js';
import {
	registrationClosedPage,
	registrationSendFailedPage
} from './registrationPages.js';
import { buildUILoginPath, buildUIPath } from './buildUIPath.js';
import type { Language } from '../i18n/languages.js';
import { lookup } from '../i18n/languages.js';
import { formatDate, formatMinutesAgo } from '../i18n/format.js';
import { text } from '../i18n/message.js';
import { uiLocalesRanges } from '../i18n/resolve.js';
import { CONSENT_TEXTS } from '../i18n/texts/consent/index.js';
import { passwordTooShort, SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import {
	SWITCH_PAGES,
	switcherFor,
	type SwitcherProps,
	type SwitchPage
} from './languageSwitch.js';
import { LANGUAGE_COOKIE, languageCookie } from '../i18n/cookie.js';

/*
 * The page language of this sign-in, decided when the interaction was created
 * (lib/actions/authorization/interactions.ts) and read by every page and message of it, so no step changes
 * language halfway. A record written before the field existed falls back to the application's request.
 */
function languageOf(interaction: Interaction): Language {
	return (
		interaction.payload.language ??
		lookup(uiLocalesRanges(interaction.payload.params?.ui_locales)) ??
		'en'
	);
}

/*
 * The single answer to every failed code, whatever went wrong: a guess, a replay, an expired step, or a
 * throttle. One catalogue entry, so no future branch can accidentally be more informative than the others —
 * which is the only way an attacker learns anything here.
 */
function switcherOf(
	interaction: Interaction,
	page: SwitchPage
): SwitcherProps | undefined {
	return switcherFor(
		interaction.id,
		page,
		languageOf(interaction),
		interaction.payload.alternative
	);
}

function invalidCode(interaction: Interaction): string {
	return SIGN_IN_TEXTS[languageOf(interaction)].errors.invalidCode;
}

import { ApplicationConfig, configuration } from 'lib/configs/application.js';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { signUpsPaused } from '../plans/signups.js';

/*
 * Returns an error that ended a resumed authorization request to the client that made it.
 *
 * The stored request passed redirect-URI validation when it began, but delivery goes to the
 * registration as it stands now: a client deleted, or a redirect URI withdrawn, while the end user was
 * signing in is no longer one this server may redirect to (RFC 6749 §4.1.2.1, RFC 9700 §4.11.2). The
 * refusal that says so is thrown instead, and the shared handler renders it on this server's page.
 *
 * The client is resolved here even when the pipeline already did, because an error can end the
 * request before it did — and a JWT response mode cannot be signed without one.
 */
async function deliverToClient(
	oidc: OIDCContext<PipelineParams>,
	error: unknown,
	setCookies: () => Promise<void>,
	capture: DeliveryCapture
): Promise<Response> {
	if (refusesRedirect(error)) {
		throw error;
	}
	const unknownClient = new InvalidClient(
		'client is invalid',
		'client not found'
	);
	const { client_id: clientId, redirect_uri: redirectUri } = oidc.params;
	if (clientId === undefined) {
		throw unknownClient;
	}
	const client = await Client.find(clientId, { error: unknownClient });
	if (
		typeof redirectUri !== 'string' ||
		!redirectUriAllowed(client, redirectUri)
	) {
		throw new InvalidRedirectUri();
	}
	oidc.entity('Client', client);

	// Saved first, as for a successful response: a sign-in that happened during the interaction did
	// happen, and the expired interaction cookie has to reach the browser either way.
	await setCookies();
	return deliverAuthorizationError(
		oidc,
		redirectUri,
		'UNKNOWN',
		error,
		capture
	);
}

async function resume(
	interaction: Interaction,
	cookie: OIDCCookies,
	{ route, request }: { route: string; request: Request }
) {
	/*
	 * An interaction begun from a device request is finished by the device flow, never by the redirect
	 * flow below. Every page that completes an interaction calls this function, and a device request
	 * carries no redirect URI — so before this line, a person who had to sign in or consent to approve a
	 * device was shown `invalid_redirect_uri` and the device was told nothing. Decided here, on the
	 * interaction, so no completing page has to remember it.
	 */
	if (interaction.payload.deviceCode) {
		return completeDeviceInteraction(interaction, cookie, { route, request });
	}

	/*
	 * The population this interaction belongs to, recovered from the request that started it.
	 *
	 * Nothing about the original address survives into a resumption — the browser arrives here from a
	 * sign-in screen, not from the bucket's endpoint — so the context built here would otherwise be the
	 * default bucket's, and this is where the authorization response is produced. The result was a code
	 * whose `iss` named the instance while the metadata the client discovered named the bucket, which
	 * clients reject with an error naming neither cause.
	 *
	 * The stored parameters are the ones the sign-in screen resolved its own bucket from, so the two
	 * cannot disagree.
	 */
	const bucket = await issuingBucket(
		await resolveBucketForRequest(
			clientIdOf(interaction),
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		)
	);
	const oidc = new OIDCContext<PipelineParams>({
		params: {},
		route: 'ui.resume',
		bucket,
		cookie
	});

	const setCookies = await sessionHandler(oidc);
	const confirmPage = await getResume(oidc, interaction);
	if (confirmPage) {
		// Saved first: the sign-out confirmation this page posts to reads the state it just recorded.
		await setCookies();
		return confirmPage;
	}
	cookie._interaction.set(expiredInteractionCookie(interaction.uid));

	/*
	 * From here on, anything that ends the authorization request is the client's to receive.
	 *
	 * The boundary is the restored request rather than a list of errors. Every way an interaction can
	 * fail to belong to this browser, this address or this session is raised before this line — by the
	 * guard on the route, or by `getResume` before it assigns the stored parameters — and before it there
	 * is no redirect URI to deliver to in any case. After it, an error nobody anticipated is delivered as
	 * surely as one somebody did, which a list could only promise for the errors it named.
	 */
	const capture = { surface: 'interaction' as const, route, request };
	try {
		/*
		 * The stored parameters are the ones the authorization pipeline kept after `presence` established
		 * `redirect_uri` there, so this cannot refuse a request that began at the authorization endpoint;
		 * it is what lets the response below be addressed without taking that on trust.
		 */
		presence(oidc, 'redirect_uri');

		if (oidc.result?.error) {
			const { error, error_description: errorDescription } = oidc.result;
			throw new CustomOIDCProviderError(error, errorDescription ?? '');
		}

		await checkClient(oidc);
		/*
		 * Judged against the registration as it stands now, for a code as much as for an error: the
		 * stored request was checked when it began, and a redirect URI an administrator withdrew while
		 * the end user was signing in is no longer one this server may send an authorization code to.
		 */
		const { redirect_uri: redirectUri } = oidc.params;
		if (
			typeof redirectUri !== 'string' ||
			!redirectUriAllowed(oidc.client, redirectUri)
		) {
			throw new InvalidRedirectUri();
		}
		await checkResource(oidc);
		eventBus.emit('interaction.ended', oidc);
		assignClaims(oidc);
		await loadAccount(oidc);
		await loadGrant(oidc);
		const nextStep = await interactions(oidc);
		await setCookies();
		if (nextStep) {
			return Response.redirect(nextStep, 303);
		}
		return await respond(oidc);
	} catch (err) {
		return deliverToClient(oidc, err, setCookies, capture);
	}
}

/*
 * The device flow's completion: binding the approved sign-in to the device code, or recording why it
 * failed, so the device learns the outcome on its next poll (RFC 8628 §3.5).
 *
 * Reached from `resume()` for every completing page, and from `GET /ui/:uid/device_resume`; the route
 * guard has already run in both cases.
 *
 * An outcome is recorded only after `getResume()` has restored the stored request — the boundary spec
 * 065 draws for the redirect flow. Every way a request can fail to belong to this browser, address or
 * session is raised before it, so writing an outcome onto someone's code stays out of reach of a
 * request that could not prove it is theirs. After it, every error that ends the request is recorded
 * with its own code: RFC 8628 §3.5 tells a client to stop polling on any code but the two "keep going"
 * ones, so a specific code is more use to it than a blanket `access_denied` — and the alternative was a
 * device left waiting for its code to expire.
 */
async function completeDeviceInteraction(
	interaction: Interaction,
	cookie: OIDCCookies,
	{ route, request }: { route: string; request: Request }
) {
	/* Recovered from the interaction for the reason given in `resume()` above. */
	const bucket = await issuingBucket(
		await resolveBucketForRequest(
			clientIdOf(interaction),
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		)
	);
	const oidc = new OIDCContext<PipelineParams>({
		params: {},
		route: 'ui.device_resume',
		bucket,
		cookie
	});

	const setCookies = await sessionHandler(oidc);
	const action = oidc.urlFor('code_verification');
	let code: DeviceCode | undefined;
	let restored = false;

	try {
		const confirmPage = await getResume(oidc, interaction);
		if (confirmPage) {
			// subject changed — logout confirmation self-submitting form, whose state must be saved
			await setCookies();
			return confirmPage;
		}
		restored = true;

		if (oidc.result?.error) {
			throw errorForCode(oidc.result.error, oidc.result.error_description);
		}

		cookie._interaction.set(expiredInteractionCookie(interaction.uid));

		const { deviceCode } = interaction.payload;
		if (!deviceCode) {
			throw new NotFoundError();
		}
		code = await DeviceCode.find(deviceCode, {
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
		eventBus.emit('interaction.ended', oidc);
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

		if (restored && !(err instanceof ReRenderError)) {
			const errored =
				code ??
				(interaction.payload.deviceCode
					? await DeviceCode.tryFind(interaction.payload.deviceCode, {
							ignoreExpiration: true,
							ignoreSessionBinding: true
						})
					: undefined);
			// The first outcome wins, and an expired code has already answered `expired_token`.
			if (
				errored &&
				!errored.isExpired &&
				!errored.payload.error &&
				!errored.payload.accountId
			) {
				const { error, error_description: description } = getObjFromError(
					'UNKNOWN',
					err
				);
				Object.assign(errored.payload, {
					error,
					errorDescription:
						description ??
						(error === 'access_denied'
							? 'End-User aborted interaction'
							: undefined)
				});
				await errored.save();
				/*
				 * Filed here, where the fault happened. The device's poll later answers it as a 400 — a stored
				 * outcome the token endpoint is reporting, not a failure of its own — so it is not filed twice.
				 */
				if (error === 'server_error') {
					captureFault({
						surface: 'interaction',
						route,
						method: request.method,
						status: 500,
						errorCode: 'server_error',
						error: err,
						headers: request.headers
					});
				}
				renderErr =
					error === 'access_denied'
						? new AbortedError()
						: new UnfinishedError();
			}
		}

		// The page offers the code form again, so it needs a secret the next submission can be checked against.
		const secret = crypto.randomBytes(24).toString('hex');
		oidc.session.payload.state = { secret };
		oidc.session.keep();
		await setCookies();
		return deviceInputPage({
			action,
			secret,
			err: renderErr,
			language: languageOf(interaction)
		});
	}
}

async function createGrant(
	interaction: Interaction,
	signsInto: string,
	refuse: SelectableItem[] = []
) {
	const grantId = interaction.payload.grantId;
	const details: PromptDetails = interaction.payload.prompt?.details ?? {};

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
			accountId: interaction.payload.session?.accountId,
			clientId: clientIdOf(interaction),
			bucketId: signsInto
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
			// Each member was validated as an object when the request was checked (check_rar.ts).
			if (isPlainObject(detail)) grant.addRar(detail);
		}
	}
	/*
	 * What the person left unticked (specs/093). Added above and refused here, so exactly the ticked rows
	 * remain granted; `details` holds only what was not granted before, so refusing from it never withdraws
	 * an earlier allowance.
	 */
	for (const item of refuse) {
		if (item.resource) {
			grant.rejectResourceScope(item.resource, item.scopes);
			continue;
		}
		if (item.scopes.length) grant.rejectOIDCScope(item.scopes);
		if (item.claims.length) grant.rejectOIDCClaims(item.claims);
	}

	await grant.save();
	// record the consent outcome the resume pipeline (loadExistingGrant) reads back
	interaction.payload.result = {
		...(interaction.payload.result ?? {}),
		consent: { grantId: grant.id }
	};
}

/*
 * The date until which an app keeps access it was given with `offline_access`: the grant's expiry, which
 * every refresh is bounded by and which re-consenting never extends. Formatted here, once, so the server
 * render and the browser show the same string whatever the browser's locale or clock.
 */
function lifetimeDate(exp: number, language: Language): string {
	return formatDate(language, exp * 1000);
}

function requestedAgo(iat: number | undefined, language: Language): string {
	const minutes = iat === undefined ? 0 : Math.floor((epochTime() - iat) / 60);
	if (minutes < 1) return CONSENT_TEXTS[language].warning.justNow;
	return formatMinutesAgo(language, minutes);
}

/*
 * Whether the request named the account it wants, in a way the sign-in enforces: then switching accounts
 * on the consent page can only lead back to a sign-in demanding the first one.
 */
function accountNamedByRequest(params: Record<string, unknown>): boolean {
	if (params.id_token_hint) return true;
	const raw = params.claims;
	let claims: unknown = raw;
	if (typeof raw === 'string') {
		try {
			claims = JSON.parse(raw);
		} catch {
			return false;
		}
	}
	const idToken = isPlainObject(claims)
		? (claims as { id_token?: unknown }).id_token
		: undefined;
	return isPlainObject(idToken) && idToken.sub !== undefined;
}

function asList(value: string | string[] | undefined): string[] {
	if (value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

/*
 * Declining finishes the interaction rather than throwing out of it. A throw here was rendered to the
 * browser and left the interaction standing, so the client never heard and the same uid could still be
 * resumed into a code; as a result it is consumed and delivered like any other.
 */
function decline(
	interaction: Interaction,
	cookie: OIDCCookies,
	context: { route: string; request: Request }
) {
	interaction.payload.result = {
		...(interaction.payload.result ?? {}),
		error: 'access_denied',
		error_description: 'End-User denied consent'
	};
	return resume(interaction, cookie, context);
}

/* What the person may leave out on this interaction's page — the same answer the page was drawn from. */
async function choicesFor(interaction: Interaction): Promise<ConsentChoices> {
	const clientId = clientIdOf(interaction);
	const client = clientId ? await Client.tryFind(clientId) : undefined;
	return consentChoices({
		details: interaction.payload.prompt?.details ?? {},
		partial: client?.['consent.partial'] === true,
		device: !!interaction.payload.deviceCode
	});
}

/*
 * An "Allow" that would leave the application with nothing: nothing for signing in was asked, nothing was
 * ticked, no authorization details ride along, and nothing allowed before covers this request. Answered as
 * the refusal it amounts to, without recording refusals the person expressed only by ticking nothing.
 */
async function allowsNothing(
	interaction: Interaction,
	choices: ConsentChoices,
	ticked: string[]
): Promise<boolean> {
	if (
		ticked.length ||
		choices.rar.length ||
		choices.fixed.scopes.length ||
		choices.fixed.claims.length ||
		Object.keys(choices.fixed.resourceScopes).length
	) {
		return false;
	}
	const existing = interaction.payload.grantId
		? await Grant.tryFind(interaction.payload.grantId)
		: undefined;
	if (!existing) return true;
	const params = (interaction.payload.params ?? {}) as Record<string, unknown>;
	const scopes = (typeof params.scope === 'string' ? params.scope : '')
		.split(' ')
		.filter(Boolean);
	return (
		!existing.getOIDCScopeFiltered(scopes) &&
		asList(params.resource as string | string[] | undefined).every(
			(resource) => !existing.getResourceScopeFiltered(resource, scopes)
		)
	);
}

/*
 * Everything the consent page shows, gathered from the interaction, the client, the bucket being signed
 * into, the person and their existing grant. The decisions about what to say are buildConsentView's; this
 * only reads.
 */
async function consentViewFor(
	uid: string,
	interaction: Interaction,
	signsInto: string
): Promise<ConsentView> {
	const clientId = clientIdOf(interaction) ?? '';
	const client = clientId ? await Client.tryFind(clientId) : undefined;
	const params = (interaction.payload.params ?? {}) as Record<string, unknown>;
	const details: PromptDetails = interaction.payload.prompt?.details ?? {};

	const bucket = await getBucketStore().find(signsInto);
	const service = {
		...(bucket?.displayName ? { displayName: bucket.displayName } : {}),
		host: new URL(issuerFor(bucket ?? (await issuingBucket(signsInto)))).host
	};

	const accountId = interaction.payload.session?.accountId ?? '';
	const user = accountId ? await getUserStore(signsInto).find(accountId) : null;
	const profile = user ? profileClaims(user) : {};
	// `groups` is never read from stored claims (lib/addon/account.ts says why); membership decides it.
	const { groups: _groups, ...storedClaims } = user?.claims ?? {};
	const userClaims: Record<string, unknown> = user
		? { ...storedClaims, ...profile, email: user.email }
		: {};

	const tier = client
		? await clientProvenance(client, bucket)
		: 'self-registered';
	// Read only where it could be shown: no other app's logo ever reaches the page (specs/094).
	const logo =
		tier === 'this-organization' ? await readLogo(clientId) : undefined;
	/*
	 * A client nobody registered here and that did not come through dynamic registration was resolved from
	 * its metadata document, so its client_id is a URL whose host the document proved control of.
	 */
	const documentHost =
		client &&
		tier === 'self-registered' &&
		!client.registeredDynamically &&
		!(await adapter('Client').find(clientId))
			? URL.parse(clientId)?.hostname
			: undefined;

	const existing = interaction.payload.grantId
		? await Grant.tryFind(interaction.payload.grantId)
		: undefined;
	const granted: GrantedSoFar | undefined = existing
		? {
				oidcScopes: existing.getOIDCScope().split(' ').filter(Boolean),
				oidcClaims: existing.getOIDCClaims(),
				resourceScopes: Object.fromEntries(
					Object.keys(existing.payload.resources ?? {}).map((indicator) => [
						indicator,
						existing.getResourceScope(indicator).split(' ').filter(Boolean)
					])
				),
				rar: existing.payload.rar ?? []
			}
		: undefined;
	const refused: GrantedSoFar | undefined = existing?.payload.rejected
		? {
				oidcScopes: existing.getRejectedOIDCScope().split(' ').filter(Boolean),
				oidcClaims: existing.getRejectedOIDCClaims(),
				resourceScopes: Object.fromEntries(
					Object.keys(existing.payload.rejected.resources ?? {}).map(
						(indicator) => [
							indicator,
							existing
								.getRejectedResourceScope(indicator)
								.split(' ')
								.filter(Boolean)
						]
					)
				),
				rar: []
			}
		: undefined;

	const addressed = await addressedBucketOf(interaction);
	const indicators = new Set([
		...Object.keys(details.missingResourceScopes ?? {}),
		...Object.keys(granted?.resourceScopes ?? {})
	]);
	const resources: Record<string, DeclaredResourceFacts> = {};
	for (const indicator of indicators) {
		const declared = await findDeclaredResource(
			indicator,
			namespaceOf(addressed)
		);
		if (declared) {
			resources[indicator] = {
				name: declared.name,
				...(declared.scopeDescriptions
					? { scopeDescriptions: declared.scopeDescriptions }
					: {})
			};
		}
	}

	/*
	 * Long-lived access is mentioned only when a refresh token will really be issued. `offline_access`
	 * survives on the stored request only where the request may have it (check_scope.ts), and the token
	 * endpoint issues one only to a client allowed refresh tokens while the instance supports the scope —
	 * the default refresh-token rule (lib/addon/tokens.ts). A deployment that overrides that rule is not
	 * second-guessed here.
	 */
	const requestedScopes = new Set(
		(typeof params.scope === 'string' ? params.scope : '')
			.split(' ')
			.filter(Boolean)
	);
	const refreshIssued =
		requestedScopes.has('offline_access') &&
		configuration.scopes.has('offline_access') &&
		!!client &&
		grantTypeAllowed(client, 'refresh_token');
	const grantExpiry =
		existing?.payload.exp ??
		epochTime() + ttl.Grant(new Grant({ accountId, clientId }), undefined);

	let device: ConsentView['device'];
	if (interaction.payload.deviceCode) {
		const code = await DeviceCode.tryFind(interaction.payload.deviceCode, {
			ignoreExpiration: true,
			ignoreSessionBinding: true
		});
		if (code?.payload.userCode) {
			device = {
				userCode: denormalize(
					code.payload.userCode,
					ApplicationConfig['deviceFlow.mask']
				),
				requestedAgo: requestedAgo(code.payload.iat, languageOf(interaction))
			};
		}
	}

	/*
	 * Recognised by the resource the token will be minted for, not by what the prompt found missing: the
	 * administrative MCP's only scope is `openid`, so once that is granted it vanishes from the details,
	 * and a second agent asking for the same power would be shown nothing at all.
	 */
	const adminResource = asList(
		params.resource as string | string[] | undefined
	).find(isMcpResource);

	// The view builder reads no configuration, so the type → label map is resolved here and handed in.
	const rarLabels = Object.fromEntries(
		Object.entries(ApplicationConfig['richAuthorizationRequests.types']).map(
			([type, descriptor]) => [type, descriptor.label]
		)
	);

	return buildConsentView({
		uid,
		logoSrc: versionedAsset('logo.svg'),
		service,
		client: {
			id: clientId,
			...(client?.clientName ? { name: client.clientName } : {}),
			tier,
			...(documentHost ? { documentHost } : {}),
			...(client?.redirectUris.length &&
			client.redirectUris.every(isLoopbackRedirect)
				? { loopbackOnly: true }
				: {}),
			...(logo ? { logo } : {}),
			...(client?.policyUri ? { policyUri: client.policyUri } : {}),
			...(client?.tosUri ? { tosUri: client.tosUri } : {}),
			redirectUris: client?.redirectUris ?? []
		},
		redirectUri: redirectUriOf(interaction),
		account: {
			id: accountId,
			...(user?.email ? { email: user.email } : {}),
			...(profile.name ? { name: profile.name } : {}),
			...(user?.userName ? { login: user.userName } : {})
		},
		userClaims,
		details,
		...(granted ? { granted } : {}),
		resources,
		scopeDescriptions: ApplicationConfig['consent.scopeDescriptions'],
		rarLabels,
		...(adminResource ? { adminResource } : {}),
		...(refreshIssued
			? { keepsAccessUntil: lifetimeDate(grantExpiry, languageOf(interaction)) }
			: {}),
		canSwitchAccount: !accountNamedByRequest(params),
		...(device ? { device } : {}),
		...(client?.['consent.partial'] ? { partial: true } : {}),
		...(refused ? { refused } : {}),
		/* The administrators' bucket has no connected-applications page (specs/095), so nothing to point at. */
		...(signsInto === ADMIN_BUCKET_ID
			? {}
			: {
					revokeHref: accountPageUrl(bucket ?? (await issuingBucket(signsInto)))
				})
	});
}

/*
 * The password-only doors of a federated-only bucket.
 *
 * Returned as a page rather than checked inline at five call sites, so "closed means closed everywhere" is
 * one function. Each caller invokes it **before** any other check — including registration's deliberately
 * non-committal handling of an address that already exists: with the door shut there is nothing to be
 * non-committal about, and the refusal reveals a bucket setting rather than anything about an account.
 */
/*
 * Takes the interaction rather than the client id so the bucket is resolved the way the sign-in resolves
 * it — with the resource the request names. Resolved from the client alone it was the default bucket for
 * a client that belongs to no bucket, so a federated-only bucket reached through a declared resource had its password,
 * reset and registration doors judged by the default bucket's policy and left open.
 */
async function passwordDoorClosed(
	interaction: Interaction,
	uid: string
): Promise<Response | undefined> {
	const bucket = await getBucketStore().find(
		await resolveBucketForRequest(
			clientIdOf(interaction),
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		)
	);
	// `=== false` exactly: absent means available, which is what a bucket predating the field must get.
	return bucket?.passwordLogin === false
		? passwordLoginClosedPage(uid, languageOf(interaction))
		: undefined;
}

/*
 * A correct password for an account that has not proven its address. It is told what happened and sent
 * what it needs, rather than pointed at an inbox: an account that existed before its bucket required
 * verification was never sent anything, and "check your inbox" was a dead end for it.
 *
 * Reachable only after the password was proven, so naming the address and saying a message went to it
 * reveals nothing an attacker did not already have.
 */
async function unverifiedAtSignIn(
	uid: string,
	interaction: Interaction,
	user: Pick<User, '_id' | 'email'>,
	bucket: UserBucket,
	loginOptions: LoginOptions
): Promise<Response> {
	const sent = await sendOnDemand(user, bucket, {
		reuseOutstanding: true,
		language: languageOf(interaction)
	});
	if (
		(sent.outcome === 'sent' || sent.outcome === 'outstanding') &&
		sent.method === 'code'
	) {
		return Response.redirect(
			`/verify-email/code?ref=${encodeURIComponent(sent.id)}`,
			303
		);
	}
	/*
	 * Remembered so the page can offer "send the link again" — for the person whose letter went astray
	 * while the link it carried is still valid, who otherwise could only wait for it to expire.
	 */
	interaction.payload.pendingVerification = {
		accountId: user._id,
		bucketId: bucket._id
	};
	await interaction.persist();
	const T = SIGN_IN_TEXTS[languageOf(interaction)].errors;
	const errorMessage =
		sent.outcome === 'sent'
			? text(T.verificationSent, { email: user.email })
			: sent.outcome === 'outstanding'
				? text(T.verificationOutstanding, { email: user.email })
				: sent.outcome === 'rate_limited'
					? T.verificationRecent
					: T.verificationUnsent;
	return loginServer(uid, {
		errorMessage,
		verificationResend: true,
		handOffTo: redirectUriOf(interaction),
		language: languageOf(interaction),
		switcher: switcherOf(interaction, 'login'),
		...loginOptions
	});
}

/* The client that began an interaction — the only trustworthy route to a bucket. */
function clientIdOf(interaction: Interaction): string | undefined {
	return interaction.payload.params?.client_id;
}

/*
 * The resource indicator the pending authorization request named, if it named one.
 *
 * Read from the stored interaction, never from the current request. By the time a user is typing a
 * password the original parameters live only here, and the bucket they sign in against has to be the
 * one the authorization request implied — a bucket taken from the login POST would let anyone aim an
 * interaction at another tenant's accounts, which is the same reason `clientId` above is read here too.
 */
function resourceOf(interaction: Interaction): string | string[] | undefined {
	return interaction.payload.params?.resource;
}

/*
 * The bucket whose address the authorization request that began this interaction arrived at. Recorded
 * on the interaction when it was created, and read back rather than taken from the current request for
 * the reason `clientIdOf` gives: these screens are served at the root, whatever address began them.
 * An interaction written before the field existed began at the root.
 */
async function addressedBucketOf(interaction: Interaction) {
	return issuingBucket(interaction.payload.bucketId);
}

/*
 * Where the pending authorization request hands off once this interaction resolves. Every page rendered
 * inside an interaction needs it: the browser checks that address against the policy of the document
 * whose form was submitted, because the submission's redirect chain ends there — see lib/html/csp.ts.
 */
function redirectUriOf(interaction: Interaction): string | undefined {
	return interaction.payload.params?.redirect_uri;
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
		/*
		 * The attribute set is shared with the authorization routes' schema rather than restated, because
		 * Elysia merges a schema's options into every `cookie.set()` on the routes it guards and this
		 * family writes `_session` too: `resume()` runs the session handler on *this* jar, so the login
		 * POST is where the authenticated cookie is first issued. Declared with no options, it went out
		 * with no `HttpOnly`, no `SameSite` and no `Secure` — the weakest write of the cookie decided what
		 * the browser stored.
		 */
		cookie: t.Cookie(
			{
				_interaction: t.String({
					error: 'Invalid interaction cookie'
				})
			},
			endUserCookieAttributes
		),
		/*
		 * What these routes answer, for the typed client. Every handler returns a built `Response` (a page,
		 * or a redirect), which Elysia does not validate, so this describes the traffic without checking
		 * it: a page is HTML, and a refusal is the shared error body — or an HTML page, when the form is
		 * re-rendered with its error or the caller's Accept asks for a page.
		 */
		response: PageResponses
	})
	.resolve(async ({ cookie, params, request }) => {
		const interaction = await Interaction.find(params.uid, {
			error: new SessionNotFound('interaction session not found')
		});

		/*
		 * The interaction belongs to the browser it began in.
		 *
		 * The uid is in every URL of the flow, so it is not a secret: it reaches access logs, browser
		 * history and screenshots. The cookie carries a second value, minted beside the uid and never put in
		 * a URL, and this comparison is the only thing that makes it mean anything — the guard above checks
		 * that a cookie is present, not what it says. Without it, anyone holding the uid could continue the
		 * flow from their own browser with a cookie of their choosing: after the end user's correct password
		 * that meant reading their authenticator secret off the enrolment page, enrolling their own, and
		 * leaving with a session for the account.
		 *
		 * The same refusal as an unknown uid, so the answer does not say whether the uid exists.
		 */
		const expected = interaction.payload.cookieID;
		if (!expected || !constantEquals(cookie._interaction.value, expected)) {
			throw new SessionNotFound('interaction session not found');
		}

		/*
		 * An interaction belongs to the address it began at.
		 *
		 * Before buckets had hostnames this needed no guard: every interaction was served from one origin,
		 * so carrying a uid "elsewhere" meant editing a path prefix that nothing read. A bucket host makes
		 * it a real boundary, and the failure without this check is quiet rather than loud — the sign-in
		 * completes, and the session cookie it writes lands on the origin the request arrived at while
		 * being named for the bucket the interaction belonged to. That is the shape
		 * `sessionCookieName` already warns about: the sign-in completes and then does not exist.
		 *
		 * Compared against the *interaction's* bucket rather than re-derived from the client, so this
		 * stays one comparison rather than a second opinion about which population a request concerns.
		 */
		const startedAt = interaction.payload.bucketId;
		if (startedAt) {
			const host = hostOfRequest(request);
			const arrivedAt =
				host !== null && !isCanonicalHost(host)
					? await bucketAtHost(host)
					: null;
			const startedBucket = await issuingBucket(startedAt);

			/*
			 * Checked only when a hostname is involved on one side or the other, and that qualifier is what
			 * makes this correct rather than merely strict. These pages are mounted at the root and are NOT
			 * repeated beneath a bucket's path — a path-addressed bucket's sign-in screen is served from the
			 * canonical origin, by design — so comparing the request's address against the interaction's
			 * would refuse every path-addressed sign-in there has ever been.
			 *
			 * What is genuinely new is the origin: an interaction begun at a bucket's own host may be
			 * completed only there, and a request arriving at a bucket's host may complete only that
			 * bucket's interactions.
			 */
			if (hasOwnOrigin(startedBucket) || arrivedAt) {
				if (arrivedAt?._id !== startedBucket._id) {
					throw new SessionNotFound(
						'interaction session not found at this address'
					);
				}
			}
		}

		/*
		 * A bucket scheduled for deletion has no sign-in (specs/090 R5): neither the one this interaction began
		 * at nor the one it signs into may continue a flow begun before the schedule. Answered as an
		 * interaction that does not exist, which is what its address answers too.
		 */
		const signsInto = await resolveBucketForRequest(
			clientIdOf(interaction),
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		);
		if (
			(startedAt && (await bucketIsScheduled(startedAt))) ||
			(await bucketIsScheduled(signsInto))
		) {
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

		return { interaction, signsInto };
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
			const clientId = clientIdOf(interaction);
			return loginServer(uid, {
				notice: resolveNotice(query.notice, languageOf(interaction)),
				// Only once this sign-in has proved the password of an unverified account (see the resend route).
				verificationResend:
					interaction.payload.pendingVerification !== undefined,
				handOffTo: redirectUriOf(interaction),
				language: languageOf(interaction),
				switcher: switcherOf(interaction, 'login'),
				...(await loginOptionsForClient(
					clientId,
					resourceOf(interaction),
					await addressedBucketOf(interaction)
				))
			});
		},
		{ query: t.Object({ notice: t.Optional(t.String()) }) }
	)
	.post(
		'ui/:uid/login',
		async ({ body, params: { uid }, interaction, cookie, route, request }) => {
			const clientId = clientIdOf(interaction);
			// Before the lookup, so this cannot be used to probe which addresses exist.
			const closed = await passwordDoorClosed(interaction, uid);
			if (closed) return closed;

			const bucketId = await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);
			/*
			 * Resolved once, and used twice: the throttle needs to know whether a password alone can
			 * complete a sign-in here, and the second-factor step below needs the same answer. Reading it
			 * once is not only cheaper — two lookups are two chances to disagree about one bucket.
			 */
			const loginOptions = await loginOptionsForBucket(bucketId);

			/*
			 * The one refusal this door gives. Every path that turns a sign-in away shares this expression
			 * rather than repeating its wording, which is what keeps them byte-identical: an unknown
			 * address, a wrong password, a deactivated account and a throttled attempt must be
			 * indistinguishable, and a copy of the string is a copy that can drift.
			 */
			/*
			 * The options travel with the refusal. Without them this re-render fell back to `loginServer`'s
			 * defaults — a password form and *no providers* — so every mistyped password silently removed
			 * the bucket's provider buttons from a page that had just shown them. The resolver above exists
			 * precisely so the four renderings of this page cannot disagree; it was resolved here and then
			 * not passed.
			 */
			const refuse = () =>
				loginServer(uid, {
					errorMessage:
						SIGN_IN_TEXTS[languageOf(interaction)].errors.invalidCredentials,
					handOffTo: redirectUriOf(interaction),
					language: languageOf(interaction),
					switcher: switcherOf(interaction, 'login'),
					...loginOptions
				});

			/*
			 * Before the account lookup and before any verification, so a refused attempt costs neither —
			 * which is what stops this door doubling as a CPU-exhaustion vector, since every guess against
			 * a known address used to buy a full password hash. Placed after passwordDoorClosed because a
			 * bucket with no password door has nothing to throttle.
			 */
			if (
				await isThrottled(bucketId, body.username, loginOptions.totpRequired)
			) {
				/* The address is deliberately not carried: an operator needs to see which population is
				 * under attack, not a log they could read names out of. */
				eventBus.emit('login_throttled', { bucketId });
				return refuse();
			}

			/*
			 * Counted before the lookup and the verification, and for an address with no account too, so
			 * the counter's existence — and any future divergence in this refusal — can never be read as
			 * evidence that an account exists. The check above is the cheap path for a door already shut;
			 * this is the one that holds when a burst of attempts all found it open.
			 */
			if (
				!(await recordAttempt(
					bucketId,
					body.username,
					loginOptions.totpRequired
				))
			) {
				eventBus.emit('login_throttled', { bucketId });
				return refuse();
			}

			const userStore = getUserStore(bucketId);
			const user = await userStore.findByEmail(body.username);
			if (!user) {
				return refuse();
			}
			const validPassword = await Bun.password.verify(
				body.password,
				user.password
			);
			if (!validPassword) {
				return refuse();
			}
			/*
			 * The credential was proved, so it is not being guessed — cleared here, above the remaining
			 * gates rather than beside the success at the bottom, so that an account refused for being
			 * inactive or unverified clears it too. One call site instead of four, and the property holds
			 * by position rather than by remembering to repeat it.
			 */
			await clearFailures(bucketId, body.username);
			if (!canSignIn(user)) {
				return refuse();
			}
			const loginBucket = await getBucketStore().find(bucketId);
			/*
			 * The administrators' bucket is gated like any other. Its lockout guard sits at the setting —
			 * the requirement cannot be turned on without mail delivery, or by an administrator whose own
			 * address is unproven — so the door has no exception to make.
			 */
			if (loginBucket?.emailVerificationRequired === true && !user.verified) {
				return unverifiedAtSignIn(
					uid,
					interaction,
					user,
					loginBucket,
					loginOptions
				);
			}
			/*
			 * Last, after every refusal above. The order is the point: an inactive or unverified account
			 * is turned away exactly as it was, so the second factor never becomes the step at which an
			 * account reveals that it exists.
			 */
			const { totpRequired } = loginOptions;
			if (totpRequired) {
				/*
				 * `result` is deliberately NOT written here. That is the whole of "a correct password
				 * alone establishes nothing": no session is created, no token is issued, and the
				 * authorization request stays where it is until a code arrives.
				 */
				interaction.payload.secondFactor = {
					accountId: user._id,
					/*
					 * An unchecked checkbox submits nothing, so an absent field is the decline. `transient`
					 * is the negative of what the control says, which is the trap this expression fell into:
					 * it read `=== 'on'`, marking a sign-in the end user asked to keep as one to discard.
					 */
					transient: body.remember !== 'on',
					attempts: 0
				};
				await interaction.persist();
				/*
				 * A redirect rather than a render, and that is forced rather than stylistic:
				 * loginClient.tsx reads the page name out of window.location.pathname, so a code page
				 * served at the login path hydrates into an empty root. The federated decline path
				 * redirects for the same reason.
				 */
				return Response.redirect(
					buildUIPath(uid, user.totp ? 'totp' : 'totp/enroll'),
					303
				);
			}

			interaction.payload.result = {
				login: {
					accountId: user._id,
					transient: body.remember !== 'on',
					/*
					 * The context this sign-in satisfied. A password alone, because a bucket that demands
					 * a second factor never reaches here — it stages `secondFactor` above, and the
					 * context is decided once the code is verified.
					 */
					amr: [...AMR_FOR_DISTINCTION.password],
					acr: configuration.acrMap.password
				}
			};
			await settlePendingLink(interaction.payload, bucketId);
			return resume(interaction, cookie, { route, request });
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
	 * The code step. Reached only with a `secondFactor` on the interaction, which is to say only after a
	 * password this server accepted — there is no way to arrive here by guessing a URL.
	 */
	.get('ui/:uid/totp', async ({ params: { uid }, interaction }) => {
		const pending = interaction.payload.secondFactor;
		if (!pending) {
			return Response.redirect(buildUILoginPath(uid), 303);
		}
		const bucketId = await resolveBucketForRequest(
			clientIdOf(interaction),
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		);
		const user = await getUserStore(bucketId).find(pending.accountId);
		// Enrolment cleared between the password and now: send them to set one up rather than ask for a
		// code from an authenticator they no longer have.
		if (!user?.totp) {
			return Response.redirect(buildUIPath(uid, 'totp/enroll'), 303);
		}
		return totpServer(uid, {
			mode: 'verify',
			handOffTo: redirectUriOf(interaction),
			language: languageOf(interaction),
			switcher: switcherOf(interaction, 'totp')
		});
	})
	.post(
		'ui/:uid/totp',
		async ({ body, params: { uid }, interaction, cookie, route, request }) => {
			const pending = interaction.payload.secondFactor;
			if (!pending) {
				return Response.redirect(buildUILoginPath(uid), 303);
			}

			const bucketId = await resolveBucketForRequest(
				clientIdOf(interaction),
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);
			const refuse = () =>
				totpServer(uid, {
					mode: 'verify',
					errorMessage: invalidCode(interaction),
					handOffTo: redirectUriOf(interaction),
					language: languageOf(interaction),
					switcher: switcherOf(interaction, 'totp')
				});

			if (pending.attempts >= MAX_ATTEMPTS_PER_INTERACTION) {
				return refuse();
			}

			const outcome = await verifyForAccount(
				bucketId,
				pending.accountId,
				body.code
			);

			if (!outcome.ok) {
				if (outcome.reason === 'not_enrolled') {
					return Response.redirect(buildUIPath(uid, 'totp/enroll'), 303);
				}
				interaction.payload.secondFactor = {
					...pending,
					attempts: pending.attempts + 1
				};
				await interaction.persist();
				/*
				 * One answer for every failure — wrong, replayed, and throttled alike. A distinct "too many
				 * attempts" would confirm to someone guessing that the account is real and that their
				 * guesses are landing, which is the whole of what they wanted to learn.
				 */
				return refuse();
			}

			interaction.payload.result = {
				login: {
					accountId: pending.accountId,
					transient: pending.transient,
					amr: [...AMR_FOR_DISTINCTION.multi_factor],
					acr: configuration.acrMap.multi_factor
				}
			};
			delete interaction.payload.secondFactor;
			await settlePendingLink(interaction.payload, bucketId);
			return resume(interaction, cookie, { route, request });
		},
		{ body: t.Object({ code: t.String() }) }
	)
	/*
	 * The enrolment step, reached from two directions — a registration into a requiring bucket, and a
	 * password sign-in by an account that holds no authenticator yet. One flow, because they are the
	 * same act: neither the registrant nor the existing account has a second factor, and both need one
	 * before their sign-in can complete.
	 */
	.get('ui/:uid/totp/enroll', async ({ params: { uid }, interaction }) => {
		const pending = interaction.payload.secondFactor;
		if (!pending) {
			return Response.redirect(buildUILoginPath(uid), 303);
		}

		const clientId = clientIdOf(interaction);
		const bucketId = await resolveBucketForRequest(
			clientId,
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		);
		const { totpRequired } = await loginOptionsForClient(
			clientId,
			resourceOf(interaction),
			await addressedBucketOf(interaction)
		);
		// Lowered while this person was mid-flow: there is nothing left to enrol for.
		if (!totpRequired) {
			return Response.redirect(buildUILoginPath(uid), 303);
		}

		const user = await getUserStore(bucketId).find(pending.accountId);
		if (!user) {
			return Response.redirect(buildUILoginPath(uid), 303);
		}
		if (user.totp) {
			return Response.redirect(buildUIPath(uid, 'totp'), 303);
		}

		const bucket = await getBucketStore().find(bucketId);
		const { otpauthUri, secretText } = await offerEnrollment(
			uid,
			user._id,
			bucketId,
			{ email: user.email, label: bucket?.name || 'the application' }
		);

		return totpServer(uid, {
			mode: 'enroll',
			otpauthUri,
			secretText,
			handOffTo: redirectUriOf(interaction),
			language: languageOf(interaction),
			switcher: switcherOf(interaction, 'totp/enroll')
		});
	})
	.post(
		'ui/:uid/totp/enroll',
		async ({ body, params: { uid }, interaction, cookie, route, request }) => {
			const pending = interaction.payload.secondFactor;
			if (!pending) {
				return Response.redirect(buildUILoginPath(uid), 303);
			}

			const clientId = clientIdOf(interaction);
			const bucketId = await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);

			/*
			 * The per-interaction cap and no account window. The pending secret already expires on its
			 * own, and an account-wide lockout here would let a stranger who knows an email stop a real
			 * person from ever enrolling — the throttle would become the attack.
			 */
			if (pending.attempts >= MAX_ATTEMPTS_PER_INTERACTION) {
				return Response.redirect(buildUIPath(uid, 'totp/enroll'), 303);
			}

			const outcome = await confirmEnrollment(
				uid,
				pending.accountId,
				bucketId,
				body.code
			);

			if (!outcome.ok) {
				/*
				 * The account went away between the offer and this submission. Not the enrolment page
				 * again — there is nothing to enrol — and not an error banner either, which would invite
				 * them to keep typing codes at a row that no longer exists.
				 */
				if (outcome.reason === 'gone') {
					return Response.redirect(buildUILoginPath(uid), 303);
				}
				if (outcome.reason === 'expired') {
					// A fresh secret rather than a dead form: the GET mints one.
					return Response.redirect(buildUIPath(uid, 'totp/enroll'), 303);
				}
				interaction.payload.secondFactor = {
					...pending,
					attempts: pending.attempts + 1
				};
				await interaction.persist();

				const user = await getUserStore(bucketId).find(pending.accountId);
				const bucket = await getBucketStore().find(bucketId);
				// Re-offering through the same function is what puts the SAME secret back on the page.
				const { otpauthUri, secretText } = await offerEnrollment(
					uid,
					pending.accountId,
					bucketId,
					{
						email: user?.email ?? '',
						label: bucket?.name || 'the application'
					}
				);
				return totpServer(uid, {
					mode: 'enroll',
					errorMessage: invalidCode(interaction),
					otpauthUri,
					secretText,
					handOffTo: redirectUriOf(interaction),
					language: languageOf(interaction),
					switcher: switcherOf(interaction, 'totp/enroll')
				});
			}

			interaction.payload.result = {
				login: {
					accountId: pending.accountId,
					transient: pending.transient,
					amr: [...AMR_FOR_DISTINCTION.multi_factor],
					acr: configuration.acrMap.multi_factor
				}
			};
			delete interaction.payload.secondFactor;
			await settlePendingLink(interaction.payload, bucketId);
			return resume(interaction, cookie, { route, request });
		},
		{ body: t.Object({ code: t.String() }) }
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
			const clientId = clientIdOf(interaction);
			// The bucket comes from the client that began the interaction, never from the request: a bucket
			// taken from a parameter would let anyone aim this at any tenant's provider.
			const bucketId = await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);
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
				// Discovered, or supplied by the catalogue for the one provider that publishes no metadata.
				metadata = await upstreamMetadata(provider);
			} catch (err) {
				if (err instanceof DiscoveryError) {
					eventBus.emit('federation.upstream.error', {
						providerId: provider.id,
						reason: err.reason
					});
					return federationUpstreamPage(languageOf(interaction));
				}
				throw err;
			}

			const secrets = await openPending({
				interactionUid: uid,
				bucketId,
				providerId: provider.id,
				withPkce: supportsPkce(metadata, provider)
			});

			return Response.redirect(
				/* The callback the upstream returns to belongs to this bucket, and is the address its
				 * provider record was registered with. */
				authorizationUrl(
					provider,
					metadata,
					secrets,
					await issuingBucket(bucketId)
				),
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
		async ({ params: { uid }, query, interaction, cookie, route, request }) => {
			const handoff = await consumeHandoff(query.ref, uid);
			if (!handoff?.accountId) {
				return federationExpiredPage(languageOf(interaction));
			}

			const clientId = clientIdOf(interaction);
			const bucketId = await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);
			const user = await getUserStore(bucketId).find(handoff.accountId);
			// Re-read rather than trusted from the record: an account frozen between hops must not sign in.
			if (!user || !canSignIn(user)) {
				return federationInactivePage(languageOf(interaction));
			}

			/*
			 * The address matched an account holding only a password. Nobody is signed in: the identity is
			 * kept on the interaction, whose cookie this hop is bound to, until the sign-in completes as that
			 * account at one of the password doors.
			 */
			if (handoff.link) {
				interaction.payload.pendingLink = {
					accountId: user._id,
					bucketId,
					...handoff.link
				};
				await interaction.persist();
				return Response.redirect(
					buildUILoginPath(uid, NOTICE_FEDERATION_LINK),
					303
				);
			}

			const bucket = await getBucketStore().find(bucketId);
			if (bucket?.emailVerificationRequired && !user.verified) {
				/*
				 * The same refusal a password sign-in meets, reusing the same challenge and the same notice
				 * spec 021 made real. A second verification flow would be two answers to a settled question.
				 */
				try {
					const { id, method } = await issueAndSend(user, bucket, {
						language: languageOf(interaction)
					});
					if (method === 'code') {
						return Response.redirect(
							`/verify-email/code?ref=${encodeURIComponent(id)}`,
							303
						);
					}
				} catch {
					return federationUpstreamPage(languageOf(interaction));
				}
				return Response.redirect(buildUILoginPath(uid, NOTICE_VERIFY), 303);
			}

			interaction.payload.result = {
				// No `transient`: there is no "remember me" on a federated sign-in. No `amr` either: this
				// server observed no method of its own (lib/consts/amr.ts).
				login: {
					accountId: user._id,
					acr: configuration.acrMap.federated,
					...(handoff.upstream ? { upstream: handoff.upstream } : {})
				}
			};
			await settlePendingLink(interaction.payload, bucketId);
			return resume(interaction, cookie, { route, request });
		},
		{
			params: t.Object({ uid: t.String() }),
			query: t.Object({ ref: t.String() })
		}
	)
	/*
	 * "Send the link again", for a sign-in that already proved the password of an unverified account.
	 * It takes nothing from the request: the account is the one this interaction recorded, so the button
	 * can mail only the person who just typed that account's password, and only within the resend
	 * cooldown and daily cap. Always a fresh link — asking says the last one did not arrive.
	 */
	.post(
		'ui/:uid/verification/resend',
		async ({ params: { uid }, interaction }) => {
			const pending = interaction.payload.pendingVerification;
			const bucket = pending
				? await getBucketStore().find(pending.bucketId)
				: null;
			const user =
				pending && bucket
					? await getUserStore(pending.bucketId).find(pending.accountId)
					: null;
			if (!bucket || !user || user.verified || !canSignIn(user)) {
				return Response.redirect(buildUILoginPath(uid), 303);
			}
			const sent = await sendOnDemand(user, bucket, {
				language: languageOf(interaction),
				reuseOutstanding: false
			});
			const notice =
				sent.outcome === 'sent' || sent.outcome === 'outstanding'
					? NOTICE_VERIFY_RESENT
					: sent.outcome === 'rate_limited'
						? NOTICE_VERIFY_RECENT
						: NOTICE_VERIFY_UNSENT;
			return Response.redirect(buildUILoginPath(uid, notice), 303);
		}
	)
	.get('ui/:uid/forgot-password', async ({ params: { uid }, interaction }) => {
		const closed = await passwordDoorClosed(interaction, uid);
		// There is no password to reset, so offering the form would be a dead end dressed as help.
		return (
			closed ??
			resetRequestPage(
				uid,
				undefined,
				languageOf(interaction),
				switcherOf(interaction, 'forgot-password')
			)
		);
	})
	.post(
		'ui/:uid/forgot-password',
		async ({ body, params: { uid }, interaction }) => {
			const clientId = clientIdOf(interaction);
			const closed = await passwordDoorClosed(interaction, uid);
			if (closed) return closed;

			/*
			 * The bucket comes from the client that started this interaction, never from the request. A
			 * `client_id` taken from the form would let anyone aim the lookup at any bucket, which turns a
			 * reset form into a cross-bucket address prober.
			 */
			const bucketId = await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);
			/*
			 * One page for every outcome — sent, not sent, or held back by the per-address cooldown or daily
			 * cap. The throttle exists only for an address that has an account (nothing is stored for one that
			 * does not), so a "please wait" page was itself the answer to "does this address have an account
			 * here?": asking twice within a minute told anybody. The limits still apply, silently, and the
			 * page says what they are.
			 */
			await requestPasswordReset(body.email, bucketId, languageOf(interaction));
			return resetRequestAcceptedPage(languageOf(interaction));
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
		const closed = await passwordDoorClosed(interaction, uid);
		if (closed) return closed;

		const bucket = await getBucketStore().find(
			await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			)
		);
		/* Closed by the project, or paused by its plan's active-user cap (specs/102): one page, naming neither. */
		if (bucket && (!bucket.registrationOpen || (await signUpsPaused(bucket)))) {
			return registrationClosedPage(languageOf(interaction));
		}
		return registrationServer(uid, {
			handOffTo: redirectUriOf(interaction),
			language: languageOf(interaction),
			switcher: switcherOf(interaction, 'registration')
		});
	})
	.post(
		'ui/:uid/registration',
		async ({ body, params: { uid }, interaction }) => {
			const clientId = clientIdOf(interaction);
			// Ahead of the non-committal existing-address handling below, deliberately.
			const closed = await passwordDoorClosed(interaction, uid);
			if (closed) return closed;

			const bucketId = await resolveBucketForRequest(
				clientId,
				resourceOf(interaction),
				await addressedBucketOf(interaction)
			);
			const bucket = await getBucketStore().find(bucketId);

			// A closed bucket accepts no self-service sign-ups: no account, no email. Nor does one whose plan's
			// active-user cap is reached (specs/102).
			if (
				bucket &&
				(!bucket.registrationOpen || (await signUpsPaused(bucket)))
			) {
				return registrationClosedPage(languageOf(interaction));
			}

			// The user's own form comes back with their address still in it. Neither password is echoed,
			// into the markup or the props.
			if (body.password !== body.confirmPassword) {
				return registrationServer(uid, {
					errorMessage:
						SIGN_IN_TEXTS[languageOf(interaction)].errors.passwordsDiffer,
					email: body.email,
					handOffTo: redirectUriOf(interaction),
					language: languageOf(interaction),
					switcher: switcherOf(interaction, 'registration')
				});
			}
			// Before the existing-address branch, so a short password is refused the same way whether or
			// not the address is taken — answering it differently would say which one it is.
			if (body.password.length < END_USER_PASSWORD_MIN_LENGTH) {
				return registrationServer(uid, {
					errorMessage: passwordTooShort(
						languageOf(interaction),
						END_USER_PASSWORD_MIN_LENGTH
					),
					email: body.email,
					handOffTo: redirectUriOf(interaction),
					language: languageOf(interaction),
					switcher: switcherOf(interaction, 'registration')
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

			let user;
			try {
				user = await store.create(
					body.email,
					await Bun.password.hash(body.password),
					!verificationRequired,
					undefined,
					{ passwordSet: true }
				);
			} catch (err) {
				/*
				 * Two registrations for one address can both pass the check above; the store's uniqueness
				 * refuses the second. It gets the same answer the check gives, so a race says no more about
				 * which addresses exist than a lone request does.
				 */
				if (err instanceof DuplicateEndUserError) {
					return Response.redirect(`/ui/${uid}/login`, 303);
				}
				throw err;
			}
			if (bucketId === ADMIN_BUCKET_ID) {
				await registeredAdministrator(user);
			}

			if (verificationRequired && bucket) {
				try {
					const { id, method } = await issueAndSend(user, bucket, {
						language: languageOf(interaction)
					});
					if (method === 'code') {
						return Response.redirect(
							`/verify-email/code?ref=${encodeURIComponent(id)}`,
							303
						);
					}
					return Response.redirect(buildUILoginPath(uid, NOTICE_VERIFY), 303);
				} catch {
					// Delivery failed: the account exists but is unverified; invite a retry.
					return registrationSendFailedPage(languageOf(interaction));
				}
			}

			/*
			 * After the verification handling above, so the two requirements compose rather than one
			 * replacing the other: a bucket that wants both sends the registrant to prove their address
			 * now, and meets the authenticator at their first sign-in.
			 */
			if (bucket?.totpRequired) {
				interaction.payload.secondFactor = {
					accountId: user._id,
					transient: false,
					attempts: 0
				};
				await interaction.persist();
				return Response.redirect(buildUIPath(uid, 'totp/enroll'), 303);
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
	.get('ui/:uid/consent', async ({ params: { uid }, interaction, signsInto }) =>
		consentServer(await consentViewFor(uid, interaction, signsInto), {
			handOffTo: redirectUriOf(interaction),
			language: languageOf(interaction),
			switcher: switcherOf(interaction, 'consent')
		})
	)
	.post(
		'ui/:uid/consent',
		async ({ body, interaction, signsInto, cookie, route, request }) => {
			/*
			 * The decision belongs to the account it was shown for. The page carries that account back, and a
			 * submission naming any other — the browser's session changed in another tab, or the field was
			 * dropped — is refused before anything is written: granting would hand the app the wrong
			 * person's data, and declining would end a flow the person on screen never saw. Checked ahead of
			 * both branches because `createGrant` saves at once.
			 */
			const shownFor = interaction.payload.session?.accountId ?? '';
			if (!shownFor || !constantEquals(body.accountId ?? '', shownFor)) {
				throw new SessionNotFound('session principal changed');
			}

			if (body.action === 'allow') {
				const choices = await choicesFor(interaction);
				const ticked = asList(body.allow);
				/*
				 * The offer is worked out again here rather than read from the submission: a value the page did
				 * not draw is not from this page, and the only safe answer to it is to change nothing.
				 */
				const offered = new Set(choices.selectable.map((item) => item.key));
				if (
					ticked.length &&
					(!choices.active || ticked.some((key) => !offered.has(key)))
				) {
					throw new InvalidRequest('consent selection not offered');
				}
				if (
					choices.active &&
					(await allowsNothing(interaction, choices, ticked))
				) {
					return decline(interaction, cookie, { route, request });
				}
				await createGrant(
					interaction,
					signsInto,
					choices.active
						? choices.selectable.filter((item) => !ticked.includes(item.key))
						: []
				);
				return resume(interaction, cookie, { route, request });
			}

			return decline(interaction, cookie, { route, request });
		},
		{
			body: t.Object({
				action: t.Union([t.Literal('allow'), t.Literal('cancel')]),
				// The ticked rows: one value per checkbox, so a single tick arrives as a string (specs/093).
				allow: t.Optional(
					t.Union([
						t.String({ maxLength: 2048 }),
						t.Array(t.String({ maxLength: 2048 }), { maxItems: 64 })
					])
				),
				/*
				 * Optional in the schema so a submission without it reaches the refusal above — the same
				 * answer as a mismatch — rather than a validation error that says which field was missing.
				 */
				accountId: t.Optional(t.String())
			})
		}
	)
	/*
	 * The language switch (specs/097). Inside the `ui` app, so the guard above already holds: the interaction
	 * cookie, the expiry and the host-bucket origin — the same protection every other form here relies on.
	 * Both fields are checked against closed lists: the language must be English or this visitor's own, and
	 * the page one of the interaction's pages, so the redirect is built from the uid and nothing the request
	 * says, and nothing submitted is ever written back.
	 */
	.post(
		'ui/:uid/language',
		async ({ body, params: { uid }, interaction, cookie }) => {
			const { alternative } = interaction.payload;
			const page = SWITCH_PAGES.find((p) => p === body.page);
			const language =
				body.lang === 'en' || (alternative && body.lang === alternative)
					? body.lang
					: undefined;
			if (page && language && alternative) {
				cookie[LANGUAGE_COOKIE].set(languageCookie(language));
				interaction.payload.language = language;
				interaction.payload.languageChosen = true;
				await interaction.persist();
			}
			const back = page ?? interaction.payload.prompt?.name ?? 'login';
			return Response.redirect(buildUIPath(uid, back), 303);
		},
		{
			body: t.Object({
				lang: t.Optional(t.String()),
				page: t.Optional(t.String())
			})
		}
	)
	.get('ui/:uid/resume', async ({ interaction, cookie, route, request }) =>
		resume(interaction, cookie, { route, request })
	)
	.get(
		'ui/:uid/device_resume',
		async ({ interaction, cookie, route, request }) =>
			completeDeviceInteraction(interaction, cookie, { route, request })
	);
