import { pathToFileURL } from 'node:url';
import * as path from 'node:path';

import { dirname } from 'desm';
import { beforeEach, afterEach, expect } from 'bun:test';

import base64url from 'base64url';
import { treaty } from '@elysiajs/eden';

import nanoid from '../lib/helpers/nanoid.js';
import epochTime from '../lib/helpers/epoch_time.js';
import { provider, elysia } from '../lib/index.ts';
import instance from '../lib/helpers/weak_cache.ts';
import { adapter, getUserStore, jwksStore } from '../lib/adapters/index.ts';
import { reloadJWKSKeys } from '../lib/configs/keys.ts';
import { verifyJWKs } from '../lib/configs/verifyJWKs.ts';
import { testSigningKeys } from './jwks/fixtures.js';
import sharedTestClaims from './default.config.js';
import type { User } from '../lib/adapters/types.ts';

import { TestAdapter } from './models.js';
import { AuthorizationRequest } from './AuthorizationRequest.js';
import { setAddonBaseline } from './addon_baseline.js';
import { interactionPolicy } from '../lib/addon/index.js';

// In test mode getUserStore() returns the in-memory UserStore, which exposes a
// test-only `seed()` (see lib/adapters/memory/userStore.ts). The mongo store is
// never constructed under NODE_ENV=test, so this cast is always sound here.
type SeedableUserStore = ReturnType<typeof getUserStore> & {
	seed(user: { _id: string } & Partial<Omit<User, '_id'>>): User;
};

import { ApplicationConfig } from '../lib/configs/application.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { Session } from 'lib/models/session.js';
import { ttl } from 'lib/configs/liveTime.js';
import { Grant } from 'lib/models/grant.js';
import { ISSUER } from 'lib/configs/env.js';
export { Grant } from 'lib/models/grant.js';

const applicationDefaultSettings = { ...ApplicationConfig };
const clientDefaultSettings = { ...ClientDefaults };
const testClaims = sharedTestClaims().claims;

/*
 * seedJwks
 *
 * The provider's signing keys are single-sourced from the jwksStore adapter, exactly as clients are
 * single-sourced from the Client store. So a spec that needs its own keys writes them to the store
 * and reloads, rather than passing them to provider.init. Called for every spec so one spec's keys
 * can never leak into the next.
 */
export async function seedJwks(keys: Array<Record<string, unknown>>) {
	// verifyJWKs assigns a kid to any key that lacks one (RFC 7638 thumbprint). Doing it up front
	// means the store key always equals key.kid, so clearing by kid is exact — storing a
	// kid-less key would otherwise leave an entry keyed `undefined` that no cleanup can find.
	const seeded = structuredClone(keys) as Array<Record<string, unknown>>;
	verifyJWKs({ keys: seeded } as never);

	for (const existing of await jwksStore.getAll()) {
		await jwksStore.delete(existing.kid as string);
	}
	for (const key of seeded) {
		await jwksStore.set(key.kid as string, key as never);
	}
	await reloadJWKSKeys();
}

const { info, warn } = console;
console.info = function (...args) {
	if (!args[0].includes('NOTICE: ')) info.apply(this, args);
};
console.warn = function (...args) {
	if (!args[0].includes('WARNING: ')) warn.apply(this, args);
};

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

globalThis.i = instance;

const jwt = (token: string) =>
	JSON.parse(base64url.decode(token.split('.')[1])).jti;

export const agent = treaty(elysia);

// Faithful port of oidc-provider's test helper: the leading arguments are interaction-policy
// check reasons that must be made to "pass" (i.e. never trigger a prompt) for the wrapped cases,
// and the final argument is the callback that registers the nested describe/it cases.
//
// Applied per test, not once in beforeAll: the global afterEach resets the interaction policy, so
// a single beforeAll mutation would survive only until the first test finished.
export function passInteractionChecks(...args: unknown[]) {
	const fn = args[args.length - 1] as () => void;
	const reasons = args.slice(0, -1) as string[];
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

	return fn();
}

// eden treaty types the destructured `headers` as the loose `HeadersInit`
// (`Headers | Record<string,string> | [string,string][] | undefined`), which has
// no `.get()`. Read headers off the real `response` and assert presence so callers
// get a non-null string back.
export function getHeader(response: Response, name: string): string {
	const value = response.headers.get(name);
	if (value === null) {
		throw new Error(`expected response header "${name}"`);
	}
	return value;
}

// Preload a user into the in-memory store so the DB-backed findAccount resolves
// `accountId`. Use in specs whose flow loads an account without going through
// login() (e.g. CIBA login_hint, device_resume). Defaults: active + verified.
export function seedAccount(
	accountId: string,
	overrides: Partial<Omit<User, '_id'>> = {},
	bucket = 'redfox'
): User {
	return (getUserStore(bucket) as unknown as SeedableUserStore).seed({
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
export function seedClient(
	metadata: { clientId: string } & Record<string, unknown>
): void {
	if (TestAdapter.for('Client').syncFind(metadata.clientId)) {
		throw new Error(
			`duplicate client_id '${metadata.clientId}' seeded into the Client store`
		);
	}
	adapter('Client').upsert(metadata.clientId, metadata);
}

// Extra OIDC claims that login()'s seeded user carries for the current spec.
// Conformance suites that assert full-profile or distributed-claim masking call
// setSeedClaims(...) in beforeAll (after bootstrap, which resets it to none).
let seedClaims: Record<string, unknown> | undefined;
export function setSeedClaims(claims: Record<string, unknown> | undefined) {
	seedClaims = claims;
}

export function jsonToFormUrlEncoded(json: Record<string, unknown>) {
	const searchParams = new URLSearchParams();
	for (const [key, value] of Object.entries(json)) {
		if (Array.isArray(value)) {
			value.forEach((v) => searchParams.append(key, v));
		} else {
			searchParams.append(key, String(value));
		}
	}
	return searchParams.toString();
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
	} = await import(conf);
	let clients = clientsExport;

	if (client && !clients) {
		clients = [client];
	}
	AuthorizationRequest.clients = clients;

	// Behavior functions are overridden through the addon registry, not the
	// provider config. A *.config.ts declares them via a named `addons` export
	// (a flat map of behaviour-function overrides); that becomes this spec's
	// registry baseline (see test/addon_baseline.ts).
	setAddonBaseline(addonOverrides);

	Object.assign(ApplicationConfig, applicationDefaultSettings, app || {});
	// Claims are a server setting now, not per-instance provider setup. Most specs want the
	// shared OIDC test claim set on top of the production defaults; a spec opts out or replaces
	// it by declaring `claims` in its own ApplicationConfig export (`{}` means production only).
	ApplicationConfig.claims = {
		...applicationDefaultSettings.claims,
		...(app && Object.prototype.hasOwnProperty.call(app, 'claims')
			? app.claims
			: testClaims)
	};
	Object.assign(ClientDefaults, clientDefaultSettings, clientSettings || {});

	TestAdapter.clear();
	// Each spec file starts with no extra seeded claims; claim-conformance specs
	// opt in via setSeedClaims() after this bootstrap call.
	seedClaims = undefined;

	// Keys are seeded into the store (a spec's `jwks` named export, else the shared fixtures) and
	// reloaded, so provider.init() needs no argument at all.
	await seedJwks(jwksOverride?.keys ?? testSigningKeys);

	provider.init();

	// Clients now live in the Client store (single source of truth); seed each
	// exported client so tryFindClient resolves it from the adapter.
	for (const cl of clients ?? []) {
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
		accountId = nanoid()
	}: {
		scope?: string;
		claims?: {
			id_token?: Record<string, unknown>;
			userinfo?: Record<string, unknown>;
		};
		resources?: Record<string, string>;
		rejectedScopes?: string[];
		rejectedClaims?: string[];
		accountId?: string;
	} = {}) {
		const sessionId = nanoid();
		const loginTs = epochTime();
		const expire = new Date();
		expire.setDate(expire.getDate() + 1);
		lastAccountId = accountId;

		const session = new Session({
			jti: sessionId,
			loginTs,
			accountId
		});
		lastSession = session;
		const sessionCookie = `_session=${sessionId}; path=/; expires=${expire.toGMTString()}; httponly`;

		session.payload.authorizations = {};
		const oidc = new OIDCContext({ scope, claims });

		if (oidc.params.claims && typeof oidc.params.claims !== 'string') {
			oidc.params.claims = JSON.stringify(oidc.params.claims);
		}

		for (const cl of clients) {
			const grant = new Grant({ clientId: cl.clientId, accountId });
			grant.addOIDCScope(scope);
			if (oidc.params.claims) {
				grant.addOIDCClaims(
					Object.keys(JSON.parse(oidc.params.claims).id_token || {})
				);
				grant.addOIDCClaims(
					Object.keys(JSON.parse(oidc.params.claims).userinfo || {})
				);
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
		seedAccount(accountId, seedClaims ? { claims: seedClaims } : {});
		await session.save(ttl.Session);
		return sessionCookie;
	}

	function getLastSession() {
		return lastSession;
	}

	function getSessionId() {
		return getLastSession().id;
	}

	function getSession(id?: string) {
		const sessionId = id ?? getLastSession().id;
		return TestAdapter.for('Session').syncFind(sessionId);
	}

	function getGrantId(clientId?: string) {
		const session = getSession();

		if (!clientId && client) clientId = client.clientId;
		if (!clientId && clients) clientId = clients[0].clientId;
		try {
			return session.authorizations[clientId].grantId;
		} catch (err) {
			throw new Error('getGrantId() failed');
		}
	}

	function getTokenJti(token: string) {
		try {
			return jwt(token);
		} catch (err) {}

		return token; // opaque
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
