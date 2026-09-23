import { InvalidHeaderAuthorization } from './errors.ts';
import { routeNames } from '../consts/param_list.ts';
import { eventBus } from '../event_bus.js';
import { isPlainObject } from './_/object.js';
import {
	ApplicationConfig as config,
	configuration
} from 'lib/configs/application.js';
import {
	DEFAULT_REQUEST_BUCKET,
	issuerFor,
	type RequestBucket
} from 'lib/configs/issuer.js';
import { getCertificate } from '../addon/index.js';
import { type Client } from '../models/client/types.ts';

/* Re-exported so the request pipeline can keep importing these from here, while the declaration lives
 * beside `issuerFor` — the models need it and must not reach into the request context to get it. */
export { DEFAULT_REQUEST_BUCKET, type RequestBucket };

export class OIDCContext<T extends Record<string, unknown>> {
	#requestParamClaims = null;

	#accessToken: string | null = null;
	/*
	 * The resolved client, typed. The other entities stay untyped for now: typing them means typing every
	 * token model this context holds.
	 */
	#client: Client | undefined;
	params: T;
	#headers: Record<string, string | undefined>;

	/*
	 * The population this request is addressed to, and the source of every absolute URL it produces.
	 *
	 * Defaulted rather than required, because the default bucket is the honest answer for a request to
	 * a bare path and that is what every caller outside the prefixed routes is handling. The prefixed
	 * routes set it from the address, in one place, so no individual handler can forget to — which is
	 * the failure this default would otherwise hide, a token whose `iss` disagrees with the metadata
	 * that advertised the endpoint it came from.
	 */
	bucket: RequestBucket;

	/*
	 * The population this request signs a user *into*, which is what the session cookie is named after.
	 *
	 * A second field rather than a second opinion about the first. The two answer questions the rest of
	 * this server already keeps apart — `oidc.bucket` is the address, and `resolveBucketForRequest` is
	 * the sign-in population — and at the root they genuinely differ: the default bucket and the
	 * administrators' bucket are *both* served there, so the address cannot tell them apart and only the
	 * client can. Naming the cookie after the address therefore wrote `_session_default` at `/auth` and
	 * read `_session_admin` at the resumption, which surfaced as "interaction session and authentication
	 * session mismatch" for any operator whose browser already held an end-user sign-in.
	 *
	 * It defaults to the address and has exactly one writer — the authorization pipeline, right after
	 * `checkBucket` has refused a client that is at the wrong address — so every other endpoint keeps
	 * the behaviour it had. It is deliberately NOT folded into `bucket`: that one is what `issuerFor`
	 * stamps into a token, and a bucket with no address of its own would silently change issuer.
	 */
	signInBucket: RequestBucket;

	constructor(
		params: T,
		headers: Record<string, string | undefined> = {},
		route = 'anonymous',
		bucket: RequestBucket = DEFAULT_REQUEST_BUCKET
	) {
		this.params = params;
		this.route = route;
		this.#headers = headers;
		this.bucket = bucket;
		this.signInBucket = bucket;
		this.authorization = {};
		this.redirectUriCheckPerformed = false;
		this.webMessageUriCheckPerformed = false;
		this.entities = {};
		this.claims = {};
		this.resourceServers = {};
	}

	isFapi() {
		return config['fapi.enabled'];
	}

	entity(key, value) {
		if (!this.entities) {
			throw new Error('entities not initialized');
		}
		this.entities[key] = value;

		if (key === 'Client') {
			this.#client = value;
			// `this` is the oidc context (formerly the `ctx.oidc` payload); there is no
			// `ctx` wrapper anymore, so emit the context itself as the event payload.
			eventBus.emit('assign.client', this, value);
		}
	}

	/*
	 * The 'resume' and 'device_resume' names are deliberately absent. Their only caller built the
	 * interaction record's `returnTo`, which nothing ever read — and 'resume' produced
	 * `${ISSUER}/auth/{uid}`, an address this server does not mount. The destinations the browser
	 * actually follows are built where they are used: /ui/{uid}/{prompt} in the interactions pipeline
	 * and /ui/{uid}/resume in the resume action.
	 */
	/* This request's issuer identifier — the bare one for the default bucket, `<ISSUER>/<slug>` for any
	 * other. Everything absolute this context builds hangs off it. */
	get issuer(): string {
		return issuerFor(this.bucket);
	}

	/*
	 * Concatenated rather than resolved against the issuer as a base: `new URL('/device',
	 * 'https://host/acme')` yields `https://host/device`, because a leading slash makes the path
	 * absolute and discards the base's own. Correct URL resolution, and exactly wrong here — it would
	 * hand a named bucket's end user an address in the default bucket.
	 */
	urlFor(name, opt) {
		if (name === 'code_verification') {
			return `${this.issuer}${routeNames.code_verification}`;
		}

		if (name === 'client') {
			return `${this.issuer}${routeNames.registration}/${encodeURIComponent(opt.clientId)}`;
		}

		throw new Error(`unknown route name: ${name}`);
	}

	promptPending(name) {
		if (this.route.endsWith('resume')) {
			const should = new Set([...this.prompts]);
			Object.keys(this.result || {}).forEach(Set.prototype.delete.bind(should));

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

			const claims = configuration.claimsSupported;
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

	get requestParamScopes() {
		return new Set(this.params.scope?.split(' '));
	}

	get requestParamOIDCScopes() {
		const { scopes: oidcScopes } = configuration;
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

	/*
	 * Both read `payload` because that is where the value lives: `Session` declares `acr`/`amr` on
	 * its TypeBox payload and `BaseModel` proxies nothing, so `session.acr` was `undefined` however
	 * the session was loaded. The interaction policy compares a requested ACR against this getter,
	 * so the miss made every essential `acr` request permanently unsatisfiable.
	 */
	get acr() {
		return this.session.payload.acr;
	}

	get amr() {
		return this.session.payload.amr;
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

	get client(): Client | undefined {
		return this.#client;
	}

	/*
	 * The client, for code that runs only after the request has authenticated one. Its absence there
	 * is a defect in the pipeline, not something a caller did, so it surfaces as one rather than as an
	 * OAuth refusal.
	 */
	get authenticatedClient(): Client {
		if (!this.#client) {
			throw new Error('no client has been authenticated on this request');
		}
		return this.#client;
	}

	get grant() {
		return this.entities.Grant;
	}

	get(name: string) {
		return this.#headers[name.toLowerCase()];
	}

	getClientCertificate() {
		return getCertificate(this);
	}

	getAccessToken({ acceptDPoP = false } = {}) {
		if (this.#accessToken) {
			return this.#accessToken;
		}

		const dpop = acceptDPoP && config['dpop.enabled'] && this.#headers.dpop;
		const header = this.#headers.authorization ?? '';
		const parts = header.split(' ');

		if (parts.length !== 2) {
			throw new InvalidHeaderAuthorization(
				'invalid authorization header value format'
			);
		}
		const [scheme, value] = parts;

		if (dpop && scheme.toLowerCase() !== 'dpop') {
			throw new InvalidHeaderAuthorization(
				'authorization header scheme must be `DPoP` when DPoP is used'
			);
		} else if (!dpop && scheme.toLowerCase() === 'dpop') {
			throw new InvalidHeaderAuthorization('`DPoP` header not provided');
		} else if (!dpop && scheme.toLowerCase() !== 'bearer') {
			throw new InvalidHeaderAuthorization(
				'authorization header scheme must be `Bearer`'
			);
		}

		this.#accessToken = value;
		return value;
	}
}
