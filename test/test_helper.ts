import { pathToFileURL } from 'node:url';
import * as path from 'node:path';

import { dirname } from 'desm';
import { beforeEach, afterEach, expect } from 'bun:test';

import * as base64url from 'lib/helpers/base64url.js';
import { treaty } from '@elysiajs/eden';

import nanoid from '../lib/helpers/nanoid.js';
import epochTime from '../lib/helpers/epoch_time.js';
import { elysia } from '../lib/index.ts';
import {
	adapter,
	configStore,
	getBucketStore,
	getUserStore,
	resetStoresForTests
} from '../lib/adapters/index.ts';
import {
	forgetIssuerKeys,
	invalidateRootKeys,
	rootKeys
} from '../lib/keys/issuer_keys.ts';
import { resetActivityCacheForTests } from '../lib/activity/note.ts';
import { forgetHostArrivals } from '../lib/admin/auth/hostArrivals.ts';
import {
	resetUnauthenticatedCharge,
	setUnauthenticatedChargeClock
} from '../lib/helpers/unauthenticated_charge.ts';
import {
	resetScimRateLimiter,
	setScimRateLimitClock
} from '../lib/scim/rate_limit.ts';
import { setRateLimitClock } from '../lib/plugins/rateLimit.ts';
import { clearDocumentCache } from '../lib/client_metadata_document/cache.ts';
import { forgetAllDiscovery } from '../lib/federation/discovery.ts';
import { forgetKeySets } from '../lib/federation/jwks.ts';
import { writeRootKeys } from './root_keys.js';
import { verifyJWKs } from '../lib/configs/verifyJWKs.ts';
import { UserStore as MemoryUserStore } from '../lib/adapters/memory/userStore.ts';
import { testSigningKeys } from './jwks/fixtures.js';
import sharedTestClaims from './default.config.js';
import type { User } from '../lib/adapters/types.ts';

import { TestAdapter } from './models.js';
import { present, shaped } from './shape.js';
import { Type } from '@sinclair/typebox';
import type { AddonImplementations } from 'lib/addon/types.js';
import { SessionPayload } from '../lib/models/session.ts';
import {
	AuthorizationRequest,
	type SeedClient
} from './AuthorizationRequest.js';
import { setAddonBaseline } from './addon_baseline.js';
import { interactionPolicy } from '../lib/addon/index.js';
import { base as basePolicy } from '../lib/helpers/interaction_policy/index.js';

import {
	ApplicationConfig,
	reloadConfiguration,
	settingsApplied
} from '../lib/configs/application.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { Session } from 'lib/models/session.js';
import { cookieNames, sessionCookieName } from 'lib/consts/param_list.js';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.js';
import { type ClaimsParameter } from 'lib/helpers/oidc_context.js';
import {
	forgetBucketAddresses,
	issuingBucket
} from 'lib/admin/auth/bucketAddress.js';
import { Grant } from 'lib/models/grant.js';
import { ISSUER } from 'lib/configs/env.js';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.js';
export { Grant } from 'lib/models/grant.js';

// Taken before the first spec runs, not here — see test/config_baseline.ts for why that matters.
import {
	applicationDefaultSettings,
	clientDefaultSettings
} from './config_baseline.js';
const testClaims = sharedTestClaims().claims;

/*
 * seedJwks
 *
 * The root issuer's keys are single-sourced from their records in the key store, exactly as clients are
 * single-sourced from the Client store. So a spec that needs its own keys writes them there and reloads,
 * rather than handing them to the provider. Called for every spec so one spec's keys can never leak into
 * the next.
 */
export async function seedJwks(keys: Array<Record<string, unknown>>) {
	// verifyJWKs assigns a kid to any key that lacks one (RFC 7638 thumbprint). Doing it up front
	// means the store key always equals key.kid, so clearing by kid is exact — storing a
	// kid-less key would otherwise leave an entry keyed `undefined` that no cleanup can find.
	// It is an assertion, so `seeded.keys` is a normalized JWKS[] from here on.
	const seeded = { keys: structuredClone(keys) };
	verifyJWKs(seeded);

	await writeRootKeys(seeded.keys);
	invalidateRootKeys();
	await rootKeys();
}

const { info, warn } = console;
const mentions = (args: unknown[], marker: string) =>
	typeof args[0] === 'string' && args[0].includes(marker);
console.info = function (...args: unknown[]) {
	if (!mentions(args, 'NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args: unknown[]) {
	if (!mentions(args, 'WARNING: ')) warn.apply(this, args);
};

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const jwt = (token: string): string =>
	shaped(
		Type.Object({ jti: Type.String() }),
		JSON.parse(base64url.decode(token.split('.')[1])) as unknown
	).jti;

export const agent = treaty(elysia);

/*
 * Parameters as an OAuth client puts them on the wire, in a query and a form body alike: an array of
 * strings as repeated members (`resource`, RFC 8707 §2), an object or an array of objects as one member
 * holding its JSON text (`claims`, OIDC Core §5.5; `authorization_details`, RFC 9396 §3), anything
 * else as its string. Eden cannot do this for a query — it always repeats an array's members — which
 * is why an authorization request carrying details is sent with `AuthorizationRequest.authorize()`.
 */
export function encodeParams(params: Record<string, unknown>): URLSearchParams {
	const encoded = new URLSearchParams();
	for (const [key, value] of Object.entries(params)) {
		if (value === undefined) continue;
		if (
			isPlainObject(value) ||
			(Array.isArray(value) && value.some((item) => isPlainObject(item)))
		) {
			encoded.append(key, JSON.stringify(value));
		} else if (Array.isArray(value)) {
			value.forEach((item) => encoded.append(key, String(item)));
		} else if (
			typeof value === 'string' ||
			typeof value === 'number' ||
			typeof value === 'boolean'
		) {
			encoded.append(key, String(value));
		} else {
			encoded.append(key, JSON.stringify(value));
		}
	}
	return encoded;
}

/*
 * The typed client again, sending its body as application/x-www-form-urlencoded — how an OAuth client
 * sends one (RFC 6749 §4.1.3, RFC 9126 §2.1) — where `agent` sends JSON. Eden has no form body of its
 * own, so the JSON it built is re-encoded by `encodeParams` before the request leaves.
 */
export const formAgent = treaty(elysia, {
	onRequest(_path, init) {
		if (typeof init.body !== 'string') return;
		const params: unknown = JSON.parse(init.body);
		if (!isPlainObject(params)) return;
		return {
			body: encodeParams(params).toString(),
			headers: { 'content-type': 'application/x-www-form-urlencoded' }
		};
	}
});

// Faithful port of oidc-provider's test helper: the leading arguments are interaction-policy
// check reasons that must be made to "pass" (i.e. never trigger a prompt) for the wrapped cases,
// and the final argument is the callback that registers the nested describe/it cases.
//
// Applied per test, not once in beforeAll: the global afterEach resets the interaction policy, so
// a single beforeAll mutation would survive only until the first test finished.
export function passInteractionChecks(
	...args: [...reasons: string[], cases: () => void]
) {
	const fn = args.at(-1);
	if (typeof fn !== 'function') {
		throw new TypeError('passInteractionChecks takes the cases callback last');
	}
	const reasons = args.filter((arg) => typeof arg === 'string');
	const disabled: Array<{ check: { check: unknown }; original: unknown }> = [];

	beforeEach(() => {
		// Resolved through the addon seam, which returns a stable instance — so the checks
		// mutated here are the same objects the request path will iterate.
		const policy = interactionPolicy();
		for (const prompt of policy) {
			for (const check of prompt.checks) {
				if (reasons.includes(check.reason)) {
					disabled.push({ check, original: check.check });
					check.check = () => false;
				}
			}
		}
	});

	afterEach(() => {
		for (const { check, original } of disabled) {
			check.check = original;
		}
		disabled.length = 0;
	});

	fn();
}

// eden treaty types the destructured `headers` as the loose `HeadersInit`
// (`Headers | Record<string,string> | [string,string][] | undefined`), which has
// no `.get()`. Read headers off the real `response` and assert presence so callers
// get a non-null string back.
// An interaction policy with no prompts, for a case that must never be sent to an interaction.
export function noPrompts() {
	const policy = basePolicy();
	policy.clear();
	return policy;
}

export function getHeader(response: Response, name: string): string {
	const value = response.headers.get(name);
	if (value === null) {
		throw new Error(`expected response header "${name}"`);
	}
	return value;
}

/*
 * One parameter of the URL a response redirects to, read the way a client reads it. The legacy
 * `url.parse(location, true).query` hands back `string | string[] | undefined` for a value that is
 * single by definition; this returns the string, and fails the case when the parameter is absent.
 */
export function redirectParameter(response: Response, name: string): string {
	return locationParameter(getHeader(response, 'location'), name);
}

// The whole query of the URL a response redirects to, one value per parameter.
export function redirectQuery(response: Response): Record<string, string> {
	return locationQuery(getHeader(response, 'location'));
}

export function locationQuery(location: string): Record<string, string> {
	return Object.fromEntries(new URL(location, ISSUER).searchParams);
}

export function locationParameter(location: string, name: string): string {
	const value = new URL(location, ISSUER).searchParams.get(name);
	if (value === null) {
		throw new Error(`expected a "${name}" parameter in ${location}`);
	}
	return value;
}

// Preload a user into the in-memory store so the DB-backed findAccount resolves
// `accountId`. Use in specs whose flow loads an account without going through
// login() (e.g. CIBA login_hint, device_resume). Defaults: active + verified.
/*
 * A spec's seeded claims as the account a real sign-in would read. `email` and `email_verified` are the
 * account's own fields, never stored claims (lib/consts/reserved_claims.ts), and the server derives them from
 * the account over anything stored (lib/addon/account.ts) — so a seeded address is written where the server
 * reads it, as an administrator's or a directory's would be.
 */
function seedFieldsOf(
	claims: Record<string, unknown> | undefined
): Partial<Omit<User, '_id'>> {
	if (!claims) return {};
	const { email, email_verified: verified, ...rest } = claims;
	return {
		claims: rest,
		...(typeof email === 'string' ? { email } : {}),
		...(typeof verified === 'boolean' ? { verified } : {})
	};
}

export function seedAccount(
	accountId: string,
	overrides: Partial<Omit<User, '_id'>> = {},
	bucket = 'redfox'
): User {
	const store = getUserStore(bucket);
	// Only the in-memory store can take a caller-chosen id, and it is the one every spec runs on.
	if (!(store instanceof MemoryUserStore)) {
		throw new Error('seedAccount needs the in-memory user store');
	}
	return store.seed({
		_id: accountId,
		active: true,
		verified: true,
		...overrides
	});
}

// Seed an OAuth client into the Client store so `tryFindClient` resolves it from
// the adapter — there is no static-clients config any more. Mirrors seedAccount.
// Throws on a duplicate client_id so a misconfigured spec fails loudly rather than
// silently overwriting an existing record. upsert's body is synchronous for the
// in-memory adapter, so the record is present the moment this returns.
/*
 * The session cookie's name now varies by bucket, so a spec that cares about *the* session cookie
 * rather than about which population wrote it asks for it by prefix.
 *
 * The bare `_session=` is deliberately excluded: it belongs only to a bucket addressed by a hostname of
 * its own, and the specs that read the session through this prefix sign in at path and root buckets.
 */
export const SESSION_COOKIE_PREFIX = `${cookieNames.session}_`;

/* The default bucket's session cookie name, for a spec that hands the server a cookie it built. */
export const DEFAULT_SESSION_COOKIE = sessionCookieName(DEFAULT_REQUEST_BUCKET);

export function findSessionSetCookie(
	headers: readonly string[]
): string | undefined {
	return headers.find((c) => c.startsWith(SESSION_COOKIE_PREFIX));
}

export function seedClient(
	metadata: { clientId: string } & Record<string, unknown>
): void {
	if (TestAdapter.for('Client').syncFind(metadata.clientId)) {
		throw new Error(
			`duplicate client_id '${metadata.clientId}' seeded into the Client store`
		);
	}
	void adapter('Client').upsert(metadata.clientId, metadata);
}

/*
 * Changes a seeded client's stored registration and returns the undo. A resolved client is frozen and
 * shared by every request using it, so a case that needs the client in another state changes the
 * record it is resolved from — the way an operator would — rather than the object. Changes use the
 * stored names (recognised metadata in snake_case); `undefined` removes an attribute.
 */
export async function changeClient(
	clientId: string,
	changes: Record<string, unknown>
): Promise<() => Promise<void>> {
	const stored = await adapter('Client').find(clientId);
	if (!stored) {
		throw new Error(`no client '${clientId}' is seeded in the Client store`);
	}
	const next = {
		...Object.fromEntries(
			Object.entries({ ...stored, ...changes }).filter(
				([, value]) => value !== undefined
			)
		),
		clientId
	};
	await adapter('Client').upsert(clientId, next);
	return async () => {
		await adapter('Client').upsert(clientId, stored);
	};
}

/*
 * Seed a second user bucket, complete with the project and client that route a request to it.
 *
 * A bucket on its own routes nothing: `resolveBucketForRequest` reaches a bucket through the project
 * that holds the client, so a spec seeding only the bucket record gets the default bucket back and
 * proves nothing. All three records are therefore one call, and the clientId is returned because it
 * is the only handle a request has.
 *
 * The next spec file never sees what this seeds: bootstrap() empties every store. Within one file it
 * stays until `clearSeededBuckets()`, which a file whose later cases must not find it calls.
 */
const seededBuckets: Array<{
	bucketId: string;
	clientId: string;
	formerBucketId: unknown;
}> = [];

export async function seedBucket({
	bucketId,
	name = `${bucketId} users`,
	slug,
	clientId,
	accountId,
	client = {},
	user = {}
}: {
	bucketId: string;
	name?: string;
	/* The bucket's address. Omitted where a spec only needs a second population and never addresses
	 * it — an unaddressed bucket is a real state, not a broken fixture. */
	slug?: string;
	clientId: string;
	accountId: string;
	client?: Record<string, unknown>;
	user?: Partial<Omit<User, '_id'>>;
}): Promise<{ bucketId: string; clientId: string; accountId: string }> {
	/*
	 * A bucket appearing is one of the two events the address cache says must forget it, and here it is
	 * load-bearing rather than tidy: those caches are module state, so within one file an address looked up
	 * before this seed — and remembered as nobody's, or as an earlier seed's — would still be answered from
	 * the cache. bootstrap() forgets them between files.
	 */
	forgetBucketAddresses();
	await getBucketStore().create({
		_id: bucketId,
		name,
		slug,
		ownerGroupId: 'unassigned'
	});

	/*
	 * Seeded only if the spec's own config has not already declared it. A spec that needs `login()` to
	 * build a grant for this client has to declare it there — the harness grants against the config's
	 * `clients` — and seeding it twice throws by design. Either way the client belongs to this bucket, as
	 * an administrator-created client belongs to the bucket it was created in (specs/099).
	 */
	const declared = TestAdapter.for('Client').syncFind(clientId);
	if (declared) {
		await adapter('Client').upsert(clientId, { ...declared, bucketId });
	} else {
		seedClient({
			clientId,
			clientSecret: `${clientId}-secret`,
			grantTypes: ['authorization_code', 'refresh_token'],
			responseTypes: ['code'],
			redirectUris: [`https://${bucketId}.example.com/cb`],
			...client,
			bucketId
		});
	}

	seedAccount(accountId, user, bucketId);

	seededBuckets.push({
		bucketId,
		clientId,
		formerBucketId: declared?.bucketId
	});
	return { bucketId, clientId, accountId };
}

/*
 * Makes a stored client belong to a bucket, as creating it in that bucket's Applications would (specs/099).
 * The client must already be stored: this is the binding, not a registration.
 */
export async function bindClientToBucket(
	clientId: string,
	bucketId: string
): Promise<void> {
	const stored = await adapter('Client').find(clientId);
	if (!stored) {
		throw new Error(`no client '${clientId}' is seeded in the Client store`);
	}
	await adapter('Client').upsert(clientId, { ...stored, bucketId });
}

/* Removes exactly what seedBucket created, and nothing else — for the cases later in the same file. */
export async function clearSeededBuckets(): Promise<void> {
	for (const { bucketId, clientId, formerBucketId } of seededBuckets.splice(
		0
	)) {
		const stored = await adapter('Client').find(clientId);
		if (stored) {
			const { bucketId: _seeded, ...rest } = stored;
			await adapter('Client').upsert(
				clientId,
				formerBucketId === undefined
					? rest
					: { ...rest, bucketId: formerBucketId }
			);
		}
		await getBucketStore().destroy(bucketId);
	}
	/* The other of the two events — see the note in `seedBucket`. */
	forgetBucketAddresses();
}

/*
 * Everything the process keeps between spec files, forgotten: every store (buckets, groups,
 * users, the audit trail, recorded faults, activity) and every cache derived from a store or from a
 * stubbed upstream. Each spec file starts from what its own *.config.ts and setup put there, so a case
 * cannot pass or fail by which file ran before it — an order Windows and CI do not share.
 *
 * Spies, the system clock and process.env are not here: they are restored at the file boundary itself,
 * by test/preload.ts, so a spec that never calls bootstrap() is covered too.
 */
function forgetProcessState(): void {
	resetStoresForTests();
	forgetIssuerKeys();
	forgetBucketAddresses();
	forgetHostArrivals();
	resetActivityCacheForTests();
	resetUnauthenticatedCharge();
	setUnauthenticatedChargeClock(null);
	resetScimRateLimiter();
	setScimRateLimitClock(null);
	setRateLimitClock(null);
	clearDocumentCache();
	forgetAllDiscovery();
	forgetKeySets();
}

// Extra OIDC claims that login()'s seeded user carries for the current spec.
// Conformance suites that assert full-profile or distributed-claim masking call
// setSeedClaims(...) in beforeAll (after bootstrap, which resets it to none).
let seedClaims: Record<string, unknown> | undefined;
export function setSeedClaims(claims: Record<string, unknown> | undefined) {
	seedClaims = claims;
}

// An object member (claims) is written as its JSON text, as a client sends it, not as "[object Object]".
export function jsonToFormUrlEncoded(json: Record<string, unknown>) {
	const searchParams = new URLSearchParams();
	for (const [key, value] of Object.entries(json)) {
		if (Array.isArray(value)) {
			value.forEach((v) => searchParams.append(key, String(v)));
		} else if (isPlainObject(value)) {
			searchParams.append(key, JSON.stringify(value));
		} else {
			searchParams.append(key, String(value));
		}
	}
	return searchParams.toString();
}

/*
 * What a spec's *.config.ts may export, every member optional. Loaded by path at run time, so the shape
 * is stated here rather than inferred from any one config.
 */
interface SpecConfig {
	clients?: SeedClient[];
	client?: SeedClient;
	ApplicationConfig?: Partial<typeof applicationDefaultSettings>;
	ClientDefaults?: Partial<typeof clientDefaultSettings>;
	addons?: Partial<AddonImplementations>;
	jwks?: { keys: Array<Record<string, unknown>> };
}

async function bootstrap(
	importMetaUrl: string,
	{ config: base }: { config?: string } = {}
) {
	const dir = dirname(importMetaUrl);
	base ??= path.basename(dir);

	const conf = pathToFileURL(
		path.format({ dir, base: `${base}.config.js` })
	).toString();
	const {
		clients: clientsExport,
		client,
		ApplicationConfig: app,
		ClientDefaults: clientSettings,
		addons: addonOverrides,
		jwks: jwksOverride
	} = (await import(conf)) as SpecConfig;
	const clients: SeedClient[] = clientsExport ?? (client ? [client] : []);
	AuthorizationRequest.clients = clients;

	// Behavior functions are overridden through the addon registry, not the
	// provider config. A *.config.ts declares them via a named `addons` export
	// (a flat map of behaviour-function overrides); that becomes this spec's
	// registry baseline (see test/addon_baseline.ts).
	setAddonBaseline(addonOverrides);

	Object.assign(
		ApplicationConfig,
		structuredClone(applicationDefaultSettings),
		app || {}
	);
	// Claims are a server setting now, not per-instance provider setup. Most specs want the
	// shared OIDC test claim set on top of the production defaults; a spec opts out or replaces
	// it by declaring `claims` in its own ApplicationConfig export (`{}` means production only).
	ApplicationConfig.claims = {
		...structuredClone(applicationDefaultSettings.claims),
		...(app && Object.prototype.hasOwnProperty.call(app, 'claims')
			? app.claims
			: testClaims)
	};
	Object.assign(
		ClientDefaults,
		structuredClone(clientDefaultSettings),
		clientSettings || {}
	);

	TestAdapter.clear();
	forgetProcessState();
	/*
	 * No stored settings either. A spec that saves one through the settings API leaves it in the store, and
	 * the next spec's own configuration then differs from it — so that spec's settings answers report the
	 * leftover as "not in force", by file order alone. Reset here rather than trusted to every spec's
	 * afterAll: sixteen specs save settings, and the next one to be written would have to remember too.
	 */
	await configStore.set({});
	// Each spec file starts with no extra seeded claims; claim-conformance specs
	// opt in via setSeedClaims() after this bootstrap call.
	seedClaims = undefined;

	// Keys are seeded into the store (a spec's `jwks` named export, else the shared fixtures) and
	// reloaded; the settings assigned above are re-validated and re-derived. There is no provider
	// init step — nothing is configured through the provider.
	await seedJwks(jwksOverride?.keys ?? testSigningKeys);
	reloadConfiguration();
	/*
	 * This spec's settings replace the last one's, so whatever was derived under those goes too — above
	 * all the client validation memo, which is keyed by the stored record alone. Without this, a spec
	 * resolving a record another spec had resolved under different capabilities got that spec's client,
	 * and passed or failed by file order: Windows and CI walk the specs in different orders.
	 */
	settingsApplied(Object.keys(ApplicationConfig));

	// Clients now live in the Client store (single source of truth); seed each
	// exported client so tryFindClient resolves it from the adapter.
	for (const cl of clients) {
		seedClient(cl);
	}

	let lastSession: Session;
	let lastAccountId: string;

	async function login({
		scope = 'openid',
		claims,
		resources = {},
		rejectedScopes = [],
		rejectedClaims = [],
		accountId = nanoid(),
		bucketId = DEFAULT_BUCKET_ID
	}: {
		scope?: string;
		// The claims parameter as a client sends it (a JSON string) or already parsed.
		claims?: string | ClaimsParameter;
		resources?: Record<string, string>;
		rejectedScopes?: string[];
		rejectedClaims?: string[];
		accountId?: string;
		/* The population this sign-in belongs to. Defaults to the bucket every spec's clients resolve
		 * to, so a spec that does not care about buckets never has to mention one. */
		bucketId?: string;
	} = {}) {
		const sessionId = nanoid();
		const loginTs = epochTime();
		const expire = new Date();
		expire.setDate(expire.getDate() + 1);
		lastAccountId = accountId;

		/*
		 * `bucketId` rides with `accountId` here for the same reason it does in `loginAccount`: an
		 * account identifier means nothing without the population that issued it, and a sign-in this
		 * helper produces has to look like one a real sign-in produced. Omitted, every session the suite
		 * builds would look like a record written before the field existed — which is deliberately
		 * replaced rather than treated as an identity, so the account-change gate would stop firing for
		 * the specs that exist to prove it fires.
		 */
		const session = new Session({
			jti: sessionId,
			loginTs,
			accountId,
			bucketId
		});
		lastSession = session;
		/*
		 * Named from the same derivation the server writes with, so a spec that signs into a second bucket
		 * gets a second cookie rather than overwriting the first — which is the behaviour under test.
		 */
		const cookieName = sessionCookieName(await issuingBucket(bucketId));
		const sessionCookie = `${cookieName}=${sessionId}; path=/; expires=${expire.toUTCString()}; httponly`;

		session.payload.authorizations = {};
		const requested: ClaimsParameter | undefined =
			typeof claims === 'string'
				? (JSON.parse(claims) as ClaimsParameter)
				: claims;
		for (const cl of clients) {
			const grant = new Grant({ clientId: cl.clientId, accountId });
			grant.addOIDCScope(scope);
			if (requested) {
				grant.addOIDCClaims(Object.keys(requested.id_token || {}));
				grant.addOIDCClaims(Object.keys(requested.userinfo || {}));
			}
			if (rejectedScopes.length) {
				grant.rejectOIDCScope(rejectedScopes.join(' '));
			}
			if (rejectedClaims.length) {
				grant.rejectOIDCClaims(rejectedClaims);
			}

			for (const [key, value] of Object.entries(resources)) {
				grant.addResourceScope(key, value);
			}

			const grantId = await grant.save();
			session.payload.authorizations[cl.clientId] = {
				sid: nanoid(),
				grantId
			};
		}

		// Seed a user so the DB-backed findAccount resolves this session's accountId
		// (the resolver reads getUserStore(bucket).find(sub)). Conformance clients
		// resolve to the default 'redfox' bucket via resolveBucketForClient. Any
		// spec-scoped extra claims (setSeedClaims) ride along on the record.
		seedAccount(accountId, seedFieldsOf(seedClaims), bucketId);
		await session.save();
		return sessionCookie;
	}

	function getLastSession() {
		return lastSession;
	}

	function getSessionId() {
		return getLastSession().id;
	}

	// The stored session, checked against the model's own schema, as `Session.fromStored` checks it.
	function getSession(id?: string) {
		const sessionId = id ?? getLastSession().id;
		return shaped(
			SessionPayload,
			present(
				TestAdapter.for('Session').syncFind(sessionId),
				'the session record'
			)
		);
	}

	function getGrantId(clientId?: string) {
		const session = getSession();

		if (!clientId && client) clientId = client.clientId;
		if (!clientId) clientId = clients.at(0)?.clientId;
		try {
			if (!clientId) throw new Error('no client');
			return present(session.authorizations?.[clientId]?.grantId, 'a grant');
		} catch (err) {
			throw new Error('getGrantId() failed', { cause: err });
		}
	}

	function getTokenJti(token: string) {
		try {
			return jwt(token);
		} catch {
			// Not a JWT: an opaque token is its own identifier.
		}

		return token;
	}

	function failWith(
		code: number,
		error: string,
		error_description: string,
		scope?: string
	) {
		return ({
			status,
			body,
			headers: { 'www-authenticate': wwwAuth }
		}: {
			status: number;
			body: unknown;
			headers: Record<string, string | undefined>;
		}) => {
			expect(status).toEqual(code);
			expect(body).toHaveProperty('error', error);
			expect(body).toHaveProperty('error_description', error_description);
			expect(wwwAuth).toMatch(new RegExp(`^Bearer realm="${ISSUER}"`));
			const present = error_description !== 'no access token provided';
			const check = (re: RegExp) => {
				if (present) expect(wwwAuth).toMatch(re);
				else expect(wwwAuth).not.toMatch(re);
			};
			check(new RegExp(`error="${error}"`));
			check(
				new RegExp(
					`error_description="${error_description.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}"`
				)
			);
			if (scope) check(new RegExp(`scope="${scope}"`));
		};
	}

	return {
		failWith,
		getLastSession,
		getSession,
		getAccountId() {
			return lastAccountId;
		},
		getSessionId,
		getGrantId,
		getTokenJti,
		login
	};
}

export default bootstrap;

export type Setup = Awaited<ReturnType<typeof bootstrap>>;
