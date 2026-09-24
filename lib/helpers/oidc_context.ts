import type { Cookie } from 'elysia';
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
import type { Client } from '../models/client/types.ts';
/*
 * Every model is imported for its type only. This module sits under the model graph — models reach it
 * through the addon registry — so a runtime import from here would enter that graph from the wrong end
 * (wiki/concepts/model-graph-import-order.md).
 */
import type { Session } from '../models/session.ts';
import type { Grant } from '../models/grant.ts';
import type { Interaction } from '../models/interaction.ts';
import type { PushedAuthorizationRequest } from '../models/pushed_authorization_request.ts';
import type { IdToken } from '../models/id_token.ts';
import type { AuthorizationCode } from '../models/authorization_code.ts';
import type { AccessToken } from '../models/access_token.ts';
import type { RefreshToken } from '../models/refresh_token.ts';
import type { DeviceCode } from '../models/device_code.ts';
import type { BackchannelAuthenticationRequest } from '../models/backchannel_authentication_request.ts';
import type { ClientCredentials } from '../models/client_credentials.ts';
import type { InitialAccessToken } from '../models/initial_access_token.ts';
import type { RegistrationAccessToken } from '../models/registration_access_token.ts';
import type { findAccount } from '../addon/account.ts';
import type ResourceServer from './resource_server.ts';
import type { PipelineParams } from '../consts/param_list.ts';
import type { TokenParams } from '../actions/token.ts';

/* Re-exported so the request pipeline can keep importing these from here, while the declaration lives
 * beside `issuerFor` — the models need it and must not reach into the request context to get it. */
export { DEFAULT_REQUEST_BUCKET, type RequestBucket };

export type Account = NonNullable<Awaited<ReturnType<typeof findAccount>>>;

/*
 * Everything the pipeline can resolve and place on a request, by the name it is stored under. One
 * declaration, so that storing or reading an entity is checked: the reads this replaced went through an
 * untyped bag, and two of them named fields that did not exist and read `undefined` for as long as they
 * lived (`Interaction.cid`, `Interaction.deviceCode`).
 */
export interface OIDCEntities {
	Client: Client;
	Session: Session;
	Grant: Grant;
	Account: Account;
	Interaction: Interaction;
	PushedAuthorizationRequest: PushedAuthorizationRequest;
	IdTokenHint: Awaited<ReturnType<typeof IdToken.validate>>;
	AuthorizationCode: AuthorizationCode;
	AccessToken: AccessToken;
	RefreshToken: RefreshToken;
	RotatedRefreshToken: RefreshToken;
	DeviceCode: DeviceCode;
	BackchannelAuthenticationRequest: BackchannelAuthenticationRequest;
	ClientCredentials: ClientCredentials;
	InitialAccessToken: InitialAccessToken;
	RegistrationAccessToken: RegistrationAccessToken;
	RotatedRegistrationAccessToken: RegistrationAccessToken;
}

/*
 * The requested claims by name. Each member may be any JSON value — OIDC Core §5.5 has members not
 * understood ignored — so it stays `unknown` until a reader uses it as a claim request, through
 * `claimRequest`. A type alias rather than an interface so it passes where a record is expected.
 */
export type ClaimsParameter = {
	id_token?: Record<string, unknown>;
	userinfo?: Record<string, unknown>;
	rejected?: string[];
};

export { claimRequest, type ClaimRequest } from './claim_request.ts';

/* Parameters as the seams shared by the authorization pipeline and the token endpoint see them. */
export type RequestParams = PipelineParams | TokenParams;

/* What an interaction resolved with, as the resumption hands it back. */
export interface InteractionResult {
	// What the sign-in screens write (lib/interactions/index.ts); `ts` is the sign-in time when not now.
	login?: {
		accountId: string;
		transient?: boolean;
		ts?: number;
		amr?: string[];
		acr?: string;
		[key: string]: unknown;
	};
	consent?: { grantId?: string; [key: string]: unknown };
	error?: string;
	error_description?: string;
	[key: string]: unknown;
}

export type OIDCCookies = Record<string, Cookie<unknown>>;

export interface OIDCContextInit<T> {
	params: T;
	headers?: Record<string, string | undefined>;
	route?: string;
	bucket: RequestBucket;
	cookie?: OIDCCookies;
	ip?: string;
}

export class OIDCContext<T extends Record<string, unknown> = RequestParams> {
	#requestParamClaims: Set<string> | null = null;

	#accessToken: string | null = null;
	#headers: Record<string, string | undefined>;

	/*
	 * Reassigned in three places only: a pushed or JWT-secured request replaces the parameters it
	 * carries, the device flow restores the ones its code was started with, and a client-authenticated
	 * endpoint narrows them to its own body.
	 */
	params: T;

	/*
	 * A route name ('registration', 'ui.resume') for contexts built directly, the Elysia route path
	 * ('/token') for those built by the auth plugin. Readers compare against both; unifying them would
	 * change the audience a JWT client assertion is checked against.
	 */
	readonly route: string;

	/*
	 * The population this request is addressed to, and the source of every absolute URL it produces.
	 *
	 * Required, not defaulted. It used to default to the default bucket as the honest answer for a bare
	 * path, and that default is exactly what hid the device, backchannel and registration endpoints
	 * forgetting their address: mounted beneath every bucket, they built a context without one, and a
	 * flow started at a named bucket yielded tokens whose `iss` disagreed with the metadata that
	 * advertised the endpoint. Every construction site now states its bucket.
	 */
	readonly bucket: RequestBucket;

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

	/* The request's cookie jar, on the routes that keep a session. */
	readonly cookie: OIDCCookies | undefined;

	/* The caller's address, where an endpoint records it (the device flow). */
	readonly ip: string | undefined;

	readonly entities: Partial<OIDCEntities> = {};

	claims: ClaimsParameter = {};

	resourceServers: Record<string, ResourceServer> = {};

	result: InteractionResult | undefined;

	/* The parameters a signed request object vouched for, which later checks may take on trust. */
	trusted: string[] | undefined;

	redirectUriCheckPerformed = false;

	constructor({
		params,
		headers = {},
		route = 'anonymous',
		bucket,
		cookie,
		ip
	}: OIDCContextInit<T>) {
		this.params = params;
		this.#headers = headers;
		this.route = route;
		this.bucket = bucket;
		this.signInBucket = bucket;
		this.cookie = cookie;
		this.ip = ip;
	}

	isFapi() {
		return config['fapi.enabled'];
	}

	entity<K extends keyof OIDCEntities>(
		key: K,
		value: OIDCEntities[K] | undefined
	) {
		this.entities[key] = value;

		if (key === 'Client') {
			eventBus.emit('assign.client', this, value);
		}
	}

	/*
	 * An entity the pipeline guarantees by the time the caller runs. Its absence is a defect in the
	 * pipeline, not something a caller did, so it surfaces as one — a server error recorded as a fault —
	 * rather than as an OAuth refusal addressed to the client.
	 */
	require<K extends keyof OIDCEntities>(key: K): OIDCEntities[K] {
		const value = this.entities[key];
		if (value === undefined) {
			throw new Error(`no ${key} has been resolved on this request`);
		}
		// Checked just above; TypeScript does not narrow an indexed access through a generic key.
		return value as OIDCEntities[K];
	}

	/* The cookie jar, on a route that keeps a session; asked for on one that does not, it is a defect. */
	requireCookies(): OIDCCookies {
		if (!this.cookie) {
			throw new Error('this route keeps no cookie jar');
		}
		return this.cookie;
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
	urlFor(name: 'code_verification'): string;
	urlFor(name: 'client', opt: { clientId: string }): string;
	urlFor(name: 'code_verification' | 'client', opt?: { clientId: string }) {
		if (name === 'code_verification') {
			return `${this.issuer}${routeNames.code_verification}`;
		}

		if (name === 'client' && opt) {
			return `${this.issuer}${routeNames.registration}/${encodeURIComponent(opt.clientId)}`;
		}

		throw new Error(`unknown route name: ${name}`);
	}

	promptPending(name: string) {
		if (this.route.endsWith('resume')) {
			const should = new Set([...this.prompts]);
			Object.keys(this.result || {}).forEach(Set.prototype.delete.bind(should));

			return should.has(name);
		}

		// first pass
		return this.prompts.has(name);
	}

	#stringParam(name: string): string | undefined {
		const value = this.params[name];
		return typeof value === 'string' ? value : undefined;
	}

	get requestParamClaims(): Set<string> {
		if (this.#requestParamClaims) {
			return this.#requestParamClaims;
		}
		const requestParamClaims = new Set<string>();
		const { claims: requested } = this.params;

		if (isPlainObject(requested)) {
			const claims = configuration.claimsSupported;
			for (const members of [requested.userinfo, requested.id_token]) {
				if (!isPlainObject(members)) continue;
				Object.entries(members).forEach(([claim, value]) => {
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
		return new Set(this.#stringParam('scope')?.split(' '));
	}

	get requestParamOIDCScopes() {
		const { scopes: oidcScopes } = configuration;
		return new Set(
			this.#stringParam('scope')
				?.split(' ')
				.filter(Set.prototype.has.bind(oidcScopes))
		);
	}

	get responseMode() {
		const responseMode = this.#stringParam('response_mode');
		if (responseMode !== undefined) {
			return responseMode;
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
		const prompt = this.#stringParam('prompt');
		return new Set(prompt ? prompt.split(' ') : []);
	}

	/*
	 * A getter is a guarantee: it throws when its entity is absent, because the pipeline promised it.
	 * Anything that may legitimately be absent — a grant before consent, an account before sign-in, a
	 * device code outside the device flow — is read through `entities` instead, where the `?.` says so
	 * at the call site. The half-way getters that returned `undefined` hid which of the two a reader
	 * was relying on.
	 */

	/* Read only after the session has been loaded; before that its absence is a defect. */
	get session(): Session {
		return this.require('Session');
	}

	/*
	 * The client, for code that runs after the request has resolved one — nearly all of it. Its absence
	 * there is a defect in the pipeline, not something a caller did, so it surfaces as one rather than as
	 * an OAuth refusal. The few places where no client is a legitimate state (an account lookup on the
	 * userinfo path, a logout naming no client) read `entities.Client` instead, which says so.
	 */
	get client(): Client {
		return this.require('Client');
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
