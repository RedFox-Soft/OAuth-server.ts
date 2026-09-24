import { Type as t, type Static } from '@sinclair/typebox';
import { BaseToken, BaseTokenPayload } from './base_token.js';
import { canonicalKey, canonicalKeySet } from 'lib/helpers/rar_canonical.js';
import { ttl } from '../configs/liveTime.js';

const NON_REJECTABLE_CLAIMS = new Set([
	'sub',
	'sid',
	'auth_time',
	'acr',
	'amr',
	'iss'
]);

export const GrantPayload = t.Object({
	...BaseTokenPayload.properties,
	accountId: t.Optional(t.String()),
	createdAt: t.Number(),
	lastModifiedAt: t.Number(),
	trusted: t.Boolean(),
	resources: t.Optional(t.Record(t.String(), t.String())),
	openid: t.Optional(
		t.Object({
			scope: t.Optional(t.String()),
			claims: t.Optional(t.Array(t.String()))
		})
	),
	rejected: t.Optional(
		t.Object({
			resources: t.Optional(t.Record(t.String(), t.String())),
			openid: t.Optional(
				t.Object({
					scope: t.Optional(t.String()),
					claims: t.Optional(t.Array(t.String()))
				})
			)
		})
	),
	rar: t.Optional(t.Array(t.Object({}, { additionalProperties: true })))
});
export type GrantPayloadType = Static<typeof GrantPayload>;

/*
 * What a grant records consent in: the grant's own payload, or the `rejected` record inside it, which
 * has the same shape less its own `rejected`. The functions below take either; a grant subtracts what
 * it rejected from what it granted.
 */
type Consent = {
	openid?: { scope?: string; claims?: string[] };
	resources?: Record<string, string>;
	rejected?: Consent;
};

// A scope as a caller may hand it over.
type ScopeInput = Set<string> | string[] | string;

function scopeString(scope: ScopeInput): string {
	if (scope instanceof Set) {
		return [...scope].join(' ');
	}
	if (Array.isArray(scope)) {
		return scope.join(' ');
	}
	if (typeof scope !== 'string') {
		throw new TypeError('"scope" must be a string');
	}
	return scope;
}

function cleanConsent(context: Consent) {
	if (
		context.openid &&
		!context.openid.scope &&
		(!context.openid.claims || context.openid.claims.length === 0)
	) {
		delete context.openid;
	}

	if (context.resources) {
		for (const [identifier, value] of Object.entries(context.resources)) {
			if (!value) {
				// eslint-disable-next-line @typescript-eslint/no-dynamic-delete
				delete context.resources[identifier];
			}
		}
		if (Object.keys(context.resources).length === 0) {
			delete context.resources;
		}
	}
}

function oidcScope(context: Consent): string {
	if (context.openid?.scope) {
		if (context.rejected) {
			const rejected = oidcScope(context.rejected).split(' ');
			const granted = new Set(context.openid.scope.split(' '));
			for (const scope of rejected) {
				if (scope !== 'openid') {
					granted.delete(scope);
				}
			}
			return [...granted].join(' ');
		}
		return context.openid.scope;
	}
	return '';
}

function addScope(context: Consent, input: ScopeInput) {
	const scope = scopeString(input);
	context.openid ||= {};
	if (context.openid.scope) {
		context.openid.scope = [
			...new Set([...context.openid.scope.split(' '), ...scope.split(' ')])
		].join(' ');
	} else {
		context.openid.scope = scope;
	}
}

function resourceScope(context: Consent, resource: string): string {
	if (typeof resource !== 'string') {
		throw new TypeError('"resource" must be a string');
	}
	const granted = context.resources?.[resource];
	if (granted) {
		if (context.rejected) {
			const rejected = resourceScope(context.rejected, resource).split(' ');
			const remaining = new Set(granted.split(' '));
			for (const scope of rejected) {
				remaining.delete(scope);
			}
			return [...remaining].join(' ');
		}
		return granted;
	}
	return '';
}

function addResourceScope(
	context: Consent,
	resource: string,
	input: ScopeInput
) {
	if (typeof resource !== 'string') {
		throw new TypeError('"resource" must be a string');
	}
	const scope = scopeString(input);
	context.resources ||= {};
	const existing = context.resources[resource];
	if (existing) {
		context.resources[resource] = [
			...new Set([...existing.split(' '), ...scope.split(' ')])
		].join(' ');
	} else {
		context.resources[resource] = scope;
	}
}

function oidcClaims(context: Consent): string[] {
	if (context.openid?.claims) {
		if (context.rejected) {
			const rejected = oidcClaims(context.rejected);
			const granted = new Set(context.openid.claims);
			for (const claim of rejected) {
				if (!NON_REJECTABLE_CLAIMS.has(claim)) {
					granted.delete(claim);
				}
			}
			return [...granted];
		}
		return context.openid.claims;
	}
	return [];
}

function addClaims(context: Consent, input: Set<string> | string[]) {
	let claims: unknown[];
	if (input instanceof Set) {
		claims = [...input];
	} else if (Array.isArray(input)) {
		claims = input;
	} else {
		throw new TypeError('"claims" must be an array');
	}
	const strings = claims.filter((claim) => typeof claim === 'string');
	if (strings.length !== claims.length) {
		throw new TypeError('"claims" must be an array of strings');
	}
	context.openid ||= {};
	if (context.openid.claims) {
		context.openid.claims = [
			...new Set([...context.openid.claims, ...strings])
		];
	} else {
		context.openid.claims = strings;
	}
}

export class Grant extends BaseToken<GrantPayloadType> {
	model = GrantPayload;

	get expiration(): number {
		return (this.expiresIn ||= ttl.Grant(this, this.client));
	}

	constructor(payload: Partial<GrantPayloadType> = {}) {
		super(payload);
		this.payload.createdAt ||= Date.now();
		this.payload.lastModifiedAt ||= Date.now();
		this.payload.trusted ??=
			this.client?.['consent.require'] === false || false;
	}

	clean() {
		cleanConsent(this.payload);
		if (this.payload.rejected) cleanConsent(this.payload.rejected);
	}

	async save() {
		this.clean();
		return super.save();
	}

	#rejected(): Consent {
		this.payload.rejected ||= {};
		return this.payload.rejected;
	}

	getOIDCScope() {
		return oidcScope(this.payload);
	}

	getRejectedOIDCScope() {
		return oidcScope(this.#rejected());
	}

	getOIDCScopeFiltered(filter: Set<string> | string[]) {
		if (Array.isArray(filter)) {
			filter = new Set(filter);
		}
		if (this.payload.trusted) {
			return Array.from(filter).join(' ');
		}
		const granted = this.getOIDCScope().split(' ');
		return granted.filter(Set.prototype.has.bind(filter)).join(' ');
	}

	addOIDCScope(scope: ScopeInput) {
		addScope(this.payload, scope);
	}

	rejectOIDCScope(scope: ScopeInput) {
		addScope(this.#rejected(), scope);
	}

	getOIDCScopeEncountered() {
		const granted = this.getOIDCScope().split(' ');
		const rejected = this.getRejectedOIDCScope().split(' ');
		return granted.concat(rejected).join(' ');
	}

	getResourceScope(resource: string) {
		return resourceScope(this.payload, resource);
	}

	getRejectedResourceScope(resource: string) {
		return resourceScope(this.#rejected(), resource);
	}

	getResourceScopeFiltered(resource: string, filter: Set<string> | string[]) {
		if (Array.isArray(filter)) {
			filter = new Set(filter);
		}
		if (this.payload.trusted) {
			return Array.from(filter).join(' ');
		}
		const granted = this.getResourceScope(resource).split(' ');
		return granted.filter(Set.prototype.has.bind(filter)).join(' ');
	}

	addResourceScope(resource: string, scope: ScopeInput) {
		addResourceScope(this.payload, resource, scope);
	}

	rejectResourceScope(resource: string, scope: ScopeInput) {
		addResourceScope(this.#rejected(), resource, scope);
	}

	getResourceScopeEncountered(resource: string) {
		if (typeof resource !== 'string') {
			throw new TypeError('"resource" must be a string');
		}
		const granted = this.getResourceScope(resource).split(' ');
		const rejected = this.getRejectedResourceScope(resource).split(' ');
		return granted.concat(rejected).join(' ');
	}

	getOIDCClaims() {
		return oidcClaims(this.payload);
	}

	getRejectedOIDCClaims() {
		return oidcClaims(this.#rejected());
	}

	getOIDCClaimsFiltered(filter: Set<string> | string[]) {
		if (Array.isArray(filter)) {
			filter = new Set(filter);
		}
		if (this.payload.trusted) {
			return Array.from(filter);
		}
		const granted = this.getOIDCClaims();
		return granted.filter(Set.prototype.has.bind(filter));
	}

	addOIDCClaims(claims: Set<string> | string[]) {
		addClaims(this.payload, claims);
	}

	rejectOIDCClaims(claims: Set<string> | string[]) {
		addClaims(this.#rejected(), claims);
	}

	getOIDCClaimsEncountered() {
		const granted = this.getOIDCClaims();
		const rejected = this.getRejectedOIDCClaims();
		return granted.concat(rejected);
	}

	/*
	 * Idempotent by structural identity: without this, every re-consent appends a duplicate and the
	 * grant grows without bound for as long as the client keeps asking.
	 */
	addRar(detail: Record<string, unknown>) {
		this.payload.rar ||= [];
		const key = canonicalKey(detail);
		if (this.payload.rar.some((granted) => canonicalKey(granted) === key)) {
			return;
		}
		this.payload.rar.push(detail);
	}

	/*
	 * The sibling of getOIDCScopeFiltered/getResourceScopeFiltered/getOIDCClaimsFiltered, and trusted
	 * for the same reason they are: a client that does not require consent skips the consent prompt
	 * whole, so nothing is ever recorded on its grant. Without this arm such a client would request
	 * authorization details and silently receive none.
	 *
	 * It lives on the model rather than in the overridable rarForAuthorizationCode default so that a
	 * deployment shaping its own details cannot lose trusted-client handling.
	 */
	getRarFiltered(requested: unknown) {
		if (!Array.isArray(requested)) {
			return [];
		}
		if (this.payload.trusted) {
			return requested;
		}
		const granted = canonicalKeySet(this.payload.rar);
		return requested.filter((detail) => granted.has(canonicalKey(detail)));
	}
}
