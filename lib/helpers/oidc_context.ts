import events from 'node:events';

import isPlainObject from './_/is_plain_object.ts';
import { InvalidRequest } from './errors.ts';
import instance from './weak_cache.ts';
import { routeNames } from '../consts/param_list.ts';

export default function getContext(provider) {
	const {
		features: { dPoP: dPoPConfig, fapi },
		scopes: oidcScopes
	} = instance(provider).configuration;

	class OIDCContext extends events.EventEmitter {
		#requestParamClaims = null;

		#accessToken = null;

		#fapiProfile = null;

		constructor(ctx) {
			super();
			this.ctx = ctx;
			this.route = ctx._matchedRouteName;
			this.authorization = {};
			this.redirectUriCheckPerformed = false;
			this.webMessageUriCheckPerformed = false;
			this.entities = {};
			this.claims = {};
			this.resourceServers = {};
		}

		get fapiProfile() {
			if (this.#fapiProfile === null) {
				this.#fapiProfile = fapi.profile(this.ctx, this.client);
			}

			return this.#fapiProfile;
		}

		isFapi(...oneOf) {
			const i = oneOf.indexOf(this.fapiProfile);
			return i !== -1 ? oneOf[i] : undefined;
		}

		get issuer() {
			// eslint-disable-line class-methods-use-this
			return provider.issuer;
		}

		get provider() {
			// eslint-disable-line class-methods-use-this
			return provider;
		}

		entity(key, value) {
			if (!this.entities) {
				throw new Error('entities not initialized');
			}
			this.entities[key] = value;

			if (key === 'Client') {
				this.emit('assign.client', this.ctx, value);
			}
		}

		urlFor(name, opt) {
			const baseUrl = this.ctx.baseUrl;
			if (name === 'resume') {
				return new URL(
					`${routeNames.authorization}/${opt.uid}`,
					baseUrl
				).toString();
			}

			throw new Error(`unknown route name: ${name}`);
		}

		promptPending(name) {
			if (this.route.endsWith('resume')) {
				const should = new Set([...this.prompts]);
				Object.keys(this.result || {}).forEach(
					Set.prototype.delete.bind(should)
				);

				return should.has(name);
			}

			// first pass
			return this.prompts.has(name);
		}

		get requestParamClaims() {
			if (this.#requestParamClaims) {
				return this.#requestParamClaims;
			}
			const requestParamClaims = new Set();

			if (this.params.claims) {
				const { userinfo, id_token: idToken } = this.params.claims;

				const claims = instance(provider).configuration.claimsSupported;
				if (userinfo) {
					Object.entries(userinfo).forEach(([claim, value]) => {
						if (claims.has(claim) && (value === null || isPlainObject(value))) {
							requestParamClaims.add(claim);
						}
					});
				}

				if (idToken) {
					Object.entries(idToken).forEach(([claim, value]) => {
						if (claims.has(claim) && (value === null || isPlainObject(value))) {
							requestParamClaims.add(claim);
						}
					});
				}
			}

			this.#requestParamClaims = requestParamClaims;

			return requestParamClaims;
		}

		clientJwtAuthExpectedAudience() {
			return new Set([
				this.issuer,
				this.urlFor('token'),
				this.urlFor(this.route)
			]);
		}

		get requestParamScopes() {
			return new Set(this.params.scope?.split(' '));
		}

		get requestParamOIDCScopes() {
			return new Set(
				this.params.scope?.split(' ').filter(Set.prototype.has.bind(oidcScopes))
			);
		}

		resolvedClaims() {
			const rejected = this.session.rejectedClaimsFor(this.params.client_id);
			const claims = structuredClone(this.claims);
			claims.rejected = [...rejected];

			return claims;
		}

		get responseMode() {
			if (typeof this.params.response_mode === 'string') {
				return this.params.response_mode;
			}

			if (this.params.response_type !== undefined) {
				return 'query';
			}

			return undefined;
		}

		get acr() {
			return this.session.acr;
		}

		get amr() {
			return this.session.amr;
		}

		get prompts() {
			return new Set(this.params.prompt ? this.params.prompt.split(' ') : []);
		}

		get registrationAccessToken() {
			return this.entities.RegistrationAccessToken;
		}

		get deviceCode() {
			return this.entities.DeviceCode;
		}

		get authorizationCode() {
			return this.entities.AuthorizationCode;
		}

		get refreshToken() {
			return this.entities.RefreshToken;
		}

		get accessToken() {
			return this.entities.AccessToken;
		}

		get account() {
			return this.entities.Account;
		}

		get client() {
			return this.entities.Client;
		}

		get grant() {
			return this.entities.Grant;
		}

		getAccessToken({ acceptDPoP = false } = {}) {
			if (this.#accessToken) {
				return this.#accessToken;
			}

			const dpop = acceptDPoP && dPoPConfig.enabled && this.ctx.headers.dpop;

			const header = this.ctx.headers.authorization;
			const parts = header.split(' ');

			if (parts.length !== 2) {
				throw new InvalidRequest('invalid authorization header value format');
			}
			const [scheme, value] = parts;

			if (dpop && scheme.toLowerCase() !== 'dpop') {
				throw new InvalidRequest(
					'authorization header scheme must be `DPoP` when DPoP is used'
				);
			} else if (!dpop && scheme.toLowerCase() === 'dpop') {
				throw new InvalidRequest('`DPoP` header not provided');
			} else if (!dpop && scheme.toLowerCase() !== 'bearer') {
				throw new InvalidRequest(
					'authorization header scheme must be `Bearer`'
				);
			}

			this.#accessToken = value;
			return value;
		}
	}

	return OIDCContext;
}
