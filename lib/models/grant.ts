import { Type as t, type Static } from '@sinclair/typebox';
import { BaseToken, BaseTokenPayload } from './base_token.js';
import consent from 'lib/helpers/interaction_policy/prompts/consent.js';

const NON_REJECTABLE_CLAIMS = new Set([
	'sub',
	'sid',
	'auth_time',
	'acr',
	'amr',
	'iss'
]);

const GrantPayload = t.Composite([
	BaseTokenPayload,
	t.Object({
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
		rar: t.Optional(t.Array(t.Unknown()))
	})
]);
type GrantPayloadType = Static<typeof GrantPayload>;

export class Grant extends BaseToken<GrantPayloadType> {
	model = GrantPayload;

	constructor(payload: Partial<GrantPayloadType> = {}) {
		super(payload);
		this.payload.createdAt ||= Date.now();
		this.payload.lastModifiedAt ||= Date.now();
		this.payload.trusted ??=
			this.client?.['consent.require'] === false || false;
	}

	clean() {
		const context = this.payload || this;
		if (
			consent.openid &&
			!context.openid.scope &&
			(!context.openid.claims || context.openid.claims.length === 0)
		) {
			delete context.openid;
		}

		if (context.resources) {
			for (const [identifier, value] of Object.entries(context.resources)) {
				if (!value) {
					delete context.resources[identifier];
				}
			}
			if (Object.keys(context.resources).length === 0) {
				delete context.resources;
			}
		}
	}

	async save(...args) {
		this.clean();
		if (this.payload.rejected) this.clean.call(this.payload.rejected);

		return super.save(...args);
	}

	getOIDCScope() {
		const context = this.payload || this;
		if (context.openid?.scope) {
			if (context.rejected) {
				const rejected = this.getOIDCScope.call(context.rejected).split(' ');
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

	getRejectedOIDCScope() {
		this.payload.rejected ||= {};
		return this.getOIDCScope.call(this.payload.rejected);
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

	addOIDCScope(scope) {
		if (scope instanceof Set) {
			scope = [...scope].join(' ');
		} else if (Array.isArray(scope)) {
			scope = scope.join(' ');
		} else if (typeof scope !== 'string') {
			throw new TypeError('"scope" must be a string');
		}
		const context = this.payload || this;
		context.openid ||= {};
		if (context.openid.scope) {
			context.openid.scope = [
				...new Set([...context.openid.scope.split(' '), ...scope.split(' ')])
			].join(' ');
		} else {
			context.openid.scope = scope;
		}
	}

	rejectOIDCScope(...args) {
		this.payload.rejected ||= {};
		this.addOIDCScope.call(this.payload.rejected, ...args);
	}

	getOIDCScopeEncountered() {
		const granted = this.getOIDCScope().split(' ');
		const rejected = this.getRejectedOIDCScope().split(' ');
		return granted.concat(rejected).join(' ');
	}

	getResourceScope(resource: string) {
		if (typeof resource !== 'string') {
			throw new TypeError('"resource" must be a string');
		}
		const context = this.payload || this;
		if (context.resources?.[resource]) {
			if (context.rejected) {
				const rejected = this.getResourceScope
					.call(context.rejected, resource)
					.split(' ');
				const granted = new Set(context.resources[resource].split(' '));
				for (const scope of rejected) {
					granted.delete(scope);
				}
				return [...granted].join(' ');
			}
			return context.resources[resource];
		}
		return '';
	}

	getRejectedResourceScope(...args) {
		this.payload.rejected ||= {};
		return this.getResourceScope.call(this.payload.rejected, ...args);
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

	addResourceScope(resource, scope) {
		if (typeof resource !== 'string') {
			throw new TypeError('"resource" must be a string');
		}
		if (scope instanceof Set) {
			scope = [...scope].join(' ');
		} else if (Array.isArray(scope)) {
			scope = scope.join(' ');
		} else if (typeof scope !== 'string') {
			throw new TypeError('"scope" must be a string');
		}
		const context = this.payload || this;
		context.resources ||= {};
		if (context.resources[resource]) {
			context.resources[resource] = [
				...new Set([
					...context.resources[resource].split(' '),
					...scope.split(' ')
				])
			].join(' ');
		} else {
			context.resources[resource] = scope;
		}
	}

	rejectResourceScope(...args) {
		this.payload.rejected ||= {};
		this.addResourceScope.call(this.payload.rejected, ...args);
	}

	getResourceScopeEncountered(resource) {
		if (typeof resource !== 'string') {
			throw new TypeError('"resource" must be a string');
		}
		const granted = this.getResourceScope(resource).split(' ');
		const rejected = this.getRejectedResourceScope(resource).split(' ');
		return granted.concat(rejected).join(' ');
	}

	getOIDCClaims() {
		const context = this.payload || this;
		if (context.openid?.claims) {
			if (context.rejected) {
				const rejected = this.getOIDCClaims.call(context.rejected);
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

	getRejectedOIDCClaims() {
		this.payload.rejected ||= {};
		return this.getOIDCClaims.call(this.payload.rejected);
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

	addOIDCClaims(claims) {
		if (claims instanceof Set) {
			claims = [...claims];
		} else if (!Array.isArray(claims)) {
			throw new TypeError('"claims" must be an array');
		}
		if (claims.some((claim) => typeof claim !== 'string')) {
			throw new TypeError('"claims" must be an array of strings');
		}
		const context = this.payload || this;
		context.openid ||= {};
		if (context.openid.claims) {
			context.openid.claims = [
				...new Set([...context.openid.claims, ...claims])
			];
		} else {
			context.openid.claims = claims;
		}
	}

	rejectOIDCClaims(...args) {
		this.payload.rejected ||= {};
		this.addOIDCClaims.call(this.payload.rejected, ...args);
	}

	getOIDCClaimsEncountered() {
		const granted = this.getOIDCClaims();
		const rejected = this.getRejectedOIDCClaims();
		return granted.concat(rejected);
	}

	addRar(detail) {
		this.payload.rar ||= [];
		this.payload.rar.push(detail);
	}
}
