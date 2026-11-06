import { getBehindProxyAppStore } from '../adapters/index.js';
import type { BehindProxyApp } from '../adapters/types.js';
import { requestBucketFor } from '../admin/auth/bucketAddress.js';
import type { RequestBucket } from '../configs/issuer.js';
import { hostOfRequest } from '../consts/request_host.js';
import { captureFault } from '../error_store/capture.js';
import { eventBus } from '../event_bus.js';
import { UnknownBucket } from '../helpers/errors.js';
import { languageOfRequest } from '../i18n/request.js';
import { sameHost } from './address.js';
import { answer, withReason } from './answers.js';
import { signAssertion } from './assertion.js';
import { believedAddress, type Believed } from './believed_address.js';
import { minuteOfWeek, nextOpeningOfAll } from './clock.js';
import {
	canonicalPath,
	decide,
	hasControlCharacter,
	type Decision,
	type Reason
} from './decide.js';
import {
	addressPage,
	closedPage,
	deniedPage,
	networkDeniedPage,
	type AddressCause
} from './pages.js';
import {
	chargeApp,
	chargeUnknown,
	checkCallerOf,
	CheckRateLimited
} from './rate_limit.js';
import {
	completeSignIn,
	returnToOf,
	SIGN_OUT_PATH,
	signOut,
	START_PATH,
	startSignIn,
	type SignInContext
} from './sign_in.js';
import {
	cookieOf,
	readAppSession,
	sessionCookieName,
	standingOf,
	type Standing
} from './session.js';
import {
	noteAddress,
	noteAllowed,
	noteAsked,
	noteMismatchedHost
} from './usage.js';

/*
 * The check a reverse proxy makes before passing a request to an app behind it (specs/122,
 * contracts/check-endpoint.md). Every answer carries `X-Auth-Reason` and `Cache-Control: no-store`, and a fault is
 * answered `500`, never `2xx`: a proxy passes the request on for any success, so an answer that could be one by
 * accident would open the app.
 */

export interface CheckRequest {
	/* Whatever the router captured: `bucket` beneath a project's segment, nothing on the bare mount. */
	params: unknown;
	request: Request;
	/* The route as Elysia declared it, for a fault's record. */
	route: string;
}

const FORWARDED_HOST = 'x-forwarded-host';
const FORWARDED_URI = 'x-forwarded-uri';
const FORWARDED_METHOD = 'x-forwarded-method';

const CALLBACK_PATH = '/_foxauth/callback';
/* The proxy self-test (specs/124 research R6): the requester's own address as this check believed it. */
const ADDRESS_PATH = '/_foxauth/address';
/* What `/_foxauth/start` accepts for a fresh sign-in, in seconds: the bounds of the condition (FR-002). */
const MIN_MAX_AGE = 300;
const MAX_MAX_AGE = 86_400;
const RESERVED = /^\/_foxauth(?:\/|$)/i;

/* Identity headers, sent empty when no person is named, so an app never reads a value a client put there. */
const IDENTITY_HEADERS = [
	'X-Auth-User',
	'X-Auth-Email',
	'X-Auth-Groups',
	'X-Auth-Assertion'
] as const;

/*
 * The one refusal for an unknown project, a project scheduled for deletion, an unknown app, another project's app
 * and a host that is not the app's address. Built by one function, so nothing about the answer — status, a header,
 * the body — can tell a caller which of the five it was, and so which ids and addresses exist.
 */
function notFound(): Response {
	return answer(403, 'not_found', {}, 'not_found');
}

function denied(reason: Reason): Response {
	return answer(403, reason, {}, reason);
}

async function addressedBucket(
	params: unknown,
	request: Request
): Promise<RequestBucket | null> {
	try {
		/* Without `includeScheduled`: a project scheduled for deletion is no project here (FR-016). */
		return await requestBucketFor(
			(params as { bucket?: string } | undefined)?.bucket,
			hostOfRequest(request)
		);
	} catch (err) {
		if (err instanceof UnknownBucket) return null;
		throw err;
	}
}

function appIdOf(params: unknown): string | undefined {
	const appId = (params as { appId?: unknown } | undefined)?.appId;
	return typeof appId === 'string' && appId !== '' ? appId : undefined;
}

function emitDecision(
	app: BehindProxyApp,
	decision: Pick<Decision, 'outcome' | 'reason' | 'rule'>,
	accountId: string | null
): void {
	eventBus.emit('behind_proxy.decision', {
		bucketId: app.bucketId,
		appId: app._id,
		outcome: decision.outcome,
		reason: decision.reason,
		rule: decision.rule,
		accountId
	});
}

/* The app this check names, if this project holds it. */
async function appOf(
	bucket: RequestBucket | null,
	params: unknown
): Promise<BehindProxyApp | null> {
	const appId = appIdOf(params);
	if (!bucket || !appId) return null;
	const app = await getBehindProxyAppStore().find(appId);
	return app && app.bucketId === bucket._id ? app : null;
}

/*
 * A request a browser makes to show a page, which can be sent to a sign-in. Anything else — a script's fetch, an
 * image, a form post — would follow a redirect to a sign-in page it cannot show, so it is told `401` instead.
 */
function isNavigation(method: string, request: Request): boolean {
	return (
		(method === 'GET' || method === 'HEAD') &&
		(request.headers.get('accept') ?? '').toLowerCase().includes('text/html')
	);
}

function queryOf(rawPath: string): URLSearchParams {
	const at = rawPath.indexOf('?');
	if (at === -1) return new URLSearchParams();
	const hash = rawPath.indexOf('#', at);
	return new URLSearchParams(
		rawPath.slice(at + 1, hash === -1 ? undefined : hash)
	);
}

/*
 * The paths on the app's host that are the endpoint's own (R1): the proxy relays them here, and they are answered
 * before any rule and never passed to the app. Decided by the canonical path, so a spelling the app would read as
 * one of them is one of them here too. Where only a status may be answered (nginx's check), nothing is done: the
 * proxy's error page calls again without `mode=status`, and that call does it.
 */
function causeOf(believed: Believed): AddressCause | null {
	const { flags } = believed;
	if (believed.address !== null) return null;
	if (!flags.keyPresent) return 'noKey';
	if (!flags.keyValid) return 'wrongKey';
	if (!flags.single) return 'several';
	return 'notPublic';
}

/* A `max_age` the start path accepts: whole seconds within the condition's bounds, or nothing. */
function maxAgeOf(value: string | null): number | undefined {
	if (value === null || !/^[0-9]{1,6}$/.test(value)) return undefined;
	const seconds = Number(value);
	return seconds >= MIN_MAX_AGE && seconds <= MAX_MAX_AGE ? seconds : undefined;
}

async function reserved(
	ctx: SignInContext,
	path: string,
	rawPath: string,
	statusOnly: boolean,
	believed: Believed
): Promise<Response> {
	if (statusOnly) return answer(403, 'reserved_path', {}, 'reserved_path');
	const query = queryOf(rawPath);
	switch (path) {
		case START_PATH: {
			const maxAge = maxAgeOf(query.get('max_age'));
			return startSignIn(
				ctx,
				returnToOf(query.get('rd'), ctx.app.address),
				'signing_in',
				{
					...(query.get('prompt') === 'login'
						? { prompt: 'login' as const }
						: {}),
					...(maxAge === undefined ? {} : { maxAge })
				}
			);
		}
		case ADDRESS_PATH:
			return withReason(
				addressPage({
					host: new URL(ctx.app.address).host,
					address: believed.address,
					cause: causeOf(believed),
					reported: believed.reported,
					language: languageOfRequest(ctx.request).language
				}),
				'address_test'
			);
		case CALLBACK_PATH:
			return completeSignIn(ctx, query);
		case SIGN_OUT_PATH:
			return signOut(ctx, query);
		default:
			return answer(404, 'reserved_path', {}, 'reserved_path');
	}
}

interface Person {
	standing: Standing;
}

async function personOf(ctx: SignInContext): Promise<Person | null> {
	const { app, bucket, request } = ctx;
	const session = await readAppSession(
		{ appId: app._id, bucketId: bucket._id },
		cookieOf(request, sessionCookieName(app._id))
	);
	if (!session) return null;
	const standing = await standingOf(session, bucket._id);
	return standing ? { standing } : null;
}

/*
 * A header carries Latin-1 at most, and what a proxy does with anything beyond ASCII differs from one to the next, so
 * an address with characters outside ASCII is sent percent-encoded as UTF-8 (RFC 3986) — `%` among them, so an app
 * decodes every value the same way. The signed statement carries the address as it is.
 */
function headerSafe(value: string): string {
	return value.replace(/[^\x20-\x24\x26-\x7e]+/gu, (run) =>
		encodeURIComponent(run)
	);
}

async function allowed(
	ctx: SignInContext,
	decision: Decision,
	person: Person | null
): Promise<Response> {
	/* A public path names no one, even for a person with a session: the app is told nobody, never somebody. */
	if (decision.reason === 'public' || !person) {
		return answer(
			200,
			decision.reason,
			Object.fromEntries(IDENTITY_HEADERS.map((name) => [name, '']))
		);
	}
	const { standing } = person;
	const groups = standing.groupIds.join(',');
	return answer(200, decision.reason, {
		'X-Auth-User': standing.accountId,
		'X-Auth-Email': headerSafe(standing.email),
		'X-Auth-Groups': groups,
		'X-Auth-Assertion': await signAssertion(
			ctx.bucket,
			ctx.app.address,
			standing
		)
	});
}

/*
 * Refused by where or when (specs/124 FR-028): decided before any session, so the page names no one and offers no
 * other account. The time page says when the path opens again, in the app's own zone.
 */
function conditionPage(
	ctx: SignInContext,
	decision: Decision,
	person: Person | null
): Response {
	const { request, app } = ctx;
	const language = languageOfRequest(
		request,
		person ? [person.standing.localeRanges] : []
	).language;
	const host = new URL(app.address).host;
	const zone = app.timeZone ?? null;
	if (decision.reason === 'not_from_network') {
		return withReason(
			networkDeniedPage({ host, reason: decision.reason, language, zone }),
			decision.reason
		);
	}
	const windowSets = (decision.conditions ?? []).flatMap((judged) =>
		judged.condition.kind === 'time' ? [judged.condition.windows] : []
	);
	const opening =
		zone && windowSets.length > 0
			? nextOpeningOfAll(windowSets, minuteOfWeek(Date.now(), zone))
			: null;
	return withReason(
		closedPage({ host, reason: decision.reason, language, zone, opening }),
		decision.reason
	);
}

function refused(
	ctx: SignInContext,
	decision: Decision,
	person: Person | null,
	navigation: boolean,
	statusOnly: boolean
): Response {
	const { reason } = decision;
	if (!navigation || statusOnly) return denied(reason);
	if (reason === 'not_from_network' || reason === 'outside_hours') {
		return conditionPage(ctx, decision, person);
	}
	if (!person) return denied(reason);
	const { request, app } = ctx;
	const language = languageOfRequest(request, [
		person.standing.localeRanges
	]).language;
	return withReason(
		deniedPage({
			host: new URL(app.address).host,
			email: person.standing.email,
			reason,
			otherAccountHref: `${SIGN_OUT_PATH}?then=start`,
			zone: app.timeZone ?? null,
			language
		}),
		reason
	);
}

async function evaluate({ params, request }: CheckRequest): Promise<Response> {
	const bucket = await addressedBucket(params, request);
	const app = await appOf(bucket, params);
	if (!bucket || !app) {
		chargeUnknown(request);
		return notFound();
	}
	chargeApp(app._id);

	const forwardedHost = request.headers.get(FORWARDED_HOST);
	const rawPath = request.headers.get(FORWARDED_URI);
	const forwardedMethod = request.headers.get(FORWARDED_METHOD);
	/* Never read as `/` or `GET`: a proxy wired to leave them out would otherwise be judged by the root's rule. */
	if (!forwardedHost || !rawPath || !forwardedMethod) {
		emitDecision(
			app,
			{ outcome: 'deny', reason: 'missing_forwarded', rule: null },
			null
		);
		return denied('missing_forwarded');
	}

	/*
	 * The one place a forwarded host is read, and an exception to "the host comes only from `Host`"
	 * (lib/consts/request_host.ts): the project and the app were chosen above from this request's own address and
	 * path, and the header can only fail this comparison, never select anything. `sameHost`, not `normaliseHost`,
	 * because a port other than 443 makes a different origin and `normaliseHost` drops every port.
	 */
	if (!sameHost(forwardedHost, app.address)) {
		/* Remembered for the Connect page in memory only, so the refusal below stays the shared one, byte for byte. */
		noteMismatchedHost(app._id, forwardedHost);
		emitDecision(
			app,
			{ outcome: 'deny', reason: 'not_found', rule: null },
			null
		);
		return notFound();
	}

	noteAsked(app);
	/*
	 * The person's address, when the proxy proves it wrote it (specs/124 FR-006). Only compared with conditions:
	 * never the caller of this check, a rate-limit key, a log line or an event.
	 */
	const believed = await believedAddress(request, bucket._id);
	noteAddress(
		{
			key: `app:${app._id}`,
			write: (seen) =>
				getBehindProxyAppStore().noteUsage(app._id, {
					...(seen.provenAt ? { addressProvenAt: seen.provenAt } : {}),
					...(seen.forgedAt ? { addressForgedAt: seen.forgedAt } : {})
				})
		},
		believed.flags
	);

	const ctx: SignInContext = { bucket, app, request };
	const method = forwardedMethod.toUpperCase();
	const statusOnly = new URL(request.url).searchParams.get('mode') === 'status';
	const canonical = canonicalPath(rawPath);
	if ('path' in canonical && RESERVED.test(canonical.path)) {
		return reserved(ctx, canonical.path, rawPath, statusOnly, believed);
	}

	const person = await personOf(ctx);
	const decision = decide({
		rules: app.rules,
		method,
		rawPath,
		person: person
			? {
					canSignIn: person.standing.canSignIn,
					groupIds: person.standing.groupIds,
					attributes: person.standing.attributes,
					signedInAt: person.standing.signedInAt
				}
			: null,
		address: believed.address,
		at: Date.now(),
		timeZone: app.timeZone ?? null
	});
	const accountId = person?.standing.accountId ?? null;
	const navigation = isNavigation(method, request);

	if (decision.outcome === 'allow') {
		/* FR-020: refused rather than sent as a header the proxy would split, or a page would mislead with. */
		if (
			person &&
			decision.reason !== 'public' &&
			(hasControlCharacter(person.standing.email) ||
				person.standing.groupNames.some(hasControlCharacter))
		) {
			const refusal = {
				...decision,
				outcome: 'deny',
				reason: 'unsafe_value'
			} as const;
			emitDecision(app, refusal, accountId);
			return denied('unsafe_value');
		}
		emitDecision(app, decision, accountId);
		if (person && decision.reason !== 'public') noteAllowed(app);
		return allowed(ctx, decision, person);
	}

	emitDecision(app, decision, accountId);
	if (decision.outcome === 'sign_in') {
		if (navigation && !statusOnly) {
			return startSignIn(
				ctx,
				returnToOf(rawPath, app.address),
				decision.reason,
				decision.maxAgeSeconds === undefined
					? {}
					: { maxAge: decision.maxAgeSeconds }
			);
		}
		return answer(401, decision.reason, {
			'WWW-Authenticate': `FoxAuth realm="${app.address}"`
		});
	}
	return refused(ctx, decision, person, navigation, statusOnly);
}

/* Where only a status may be answered, a refusal for flooding is a `403`, which nginx turns into its error page. */
function rateLimited(error: CheckRateLimited, request: Request): Response {
	const statusOnly = new URL(request.url).searchParams.get('mode') === 'status';
	return answer(
		statusOnly ? 403 : 429,
		'rate_limited',
		{ 'Retry-After': String(error.retryAfterSeconds) },
		'rate_limited'
	);
}

export async function answerCheck(input: CheckRequest): Promise<Response> {
	try {
		return await evaluate(input);
	} catch (error) {
		const { request } = input;
		if (error instanceof CheckRateLimited) return rateLimited(error, request);
		const reference = captureFault({
			surface: 'oauth',
			route: input.route,
			method: request.method,
			status: 500,
			errorCode: 'behind_proxy_fault',
			error,
			callerAddress: checkCallerOf(request),
			headers: request.headers
		});
		return answer(
			500,
			'server_error',
			{},
			reference ? `server_error (reference ${reference})` : 'server_error'
		);
	}
}
