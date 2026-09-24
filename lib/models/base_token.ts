import { Type as t, type Static, type TObject } from '@sinclair/typebox';
import {
	BaseModel,
	BaseModelPayload,
	type BaseModelPayloadType,
	type ModelClass
} from './base_model.js';
import { jwt } from './formats/jwt.js';
import { Session } from './session.js';
import { InvalidTarget } from 'lib/helpers/errors.js';
import type { Client } from './client.js';
import type ResourceServer from '../helpers/resource_server.js';

export const BaseTokenPayload = t.Object({
	...BaseModelPayload.properties,
	clientId: t.String(),
	/*
	 * The user bucket that issued this token, recorded rather than derived.
	 *
	 * Every bucket is its own issuer, so `iss` is a fact about the moment of issuance and not about the
	 * current configuration. Deriving it later — from the client, say — gets it wrong the first time a
	 * client moves between projects, and, worse, cannot answer the question RFC 7662 §2.2 makes
	 * introspection answer: `active: true` asserts that *this* authorization server issued the token, so
	 * a token of another bucket presented here has to be refused, and refusing it means knowing who
	 * issued it. A realm-confusion advisory against a Keycloak integration is the same defect from the
	 * other end — a token of one realm silently accepted by a policy configured for another.
	 *
	 * Optional because a token minted before buckets became tenants carries none, and reading its
	 * absence as the default bucket is exactly right for such a token: the default bucket's issuer is
	 * the bare one those tokens were minted with.
	 */
	bucketId: t.Optional(t.String())
});

// Session-binding fields. Composed only into session-bound token schemas (access,
// authorization code, refresh, device, backchannel) — deliberately NOT part of the shared
// BaseTokenPayload so tokens like ClientCredentials do not persist them.
export const SessionBoundPayload = t.Object({
	expiresWithSession: t.Optional(t.Boolean()),
	sessionUid: t.Optional(t.String()),
	accountId: t.Optional(t.String()),
	grantId: t.Optional(t.String())
});

// RFC 8707 Resource Indicators — composed only into schemas that persist an audience
// (access tokens and client credentials).
export const AudiencePayload = t.Object({
	aud: t.Optional(t.String())
});

export type BaseTokenPayloadType = Static<typeof BaseTokenPayload> &
	Static<typeof SessionBoundPayload> &
	Static<typeof AudiencePayload>;

/*
 * What a token is built from: members of its payload, and the client, resource server and lifetime the
 * constructor takes apart from it (the client also sets clientId). Partial, because a model fills some
 * members itself (kind, iiat, consumed) and a caller supplies the ones it knows.
 */
export type TokenInit<T> = Partial<T> & {
	client?: Client;
	resourceServer?: ResourceServer;
	expiresIn?: number;
};

// Members only some tokens carry, read by the scope and resource accessors below.
type GrantedPayload = { scope?: string; resource?: string | string[] };

// A token class as its static finders use it.
type TokenClass<A, T> = (new (payload: A) => T) &
	Pick<
		typeof BaseToken,
		'adapter' | 'verify' | 'notFoundError' | 'isSessionBound'
	>;

export class BaseToken<
	T extends BaseTokenPayloadType & GrantedPayload = BaseTokenPayloadType
> extends BaseModel<T> {
	model: TObject = BaseTokenPayload;
	#client: Client | undefined;

	#resourceServer: ResourceServer | undefined;

	// Seconds this token is issued for: given at construction, or computed once from its lifetime.
	expiresIn?: number;

	constructor(init: TokenInit<T> = {}) {
		// The payload is what init carries apart from the three members the constructor takes apart.
		const payload: Partial<T> = { ...init };
		for (const member of ['client', 'resourceServer', 'expiresIn']) {
			Reflect.deleteProperty(payload, member);
		}
		super(payload);
		const { client, resourceServer, expiresIn } = init;
		if (typeof client !== 'undefined') {
			this.client = client;
		}
		if (typeof resourceServer !== 'undefined') {
			this.resourceServer = resourceServer;
		}
		if (typeof expiresIn !== 'undefined') {
			this.expiresIn = expiresIn;
		}
	}

	set client(client: Client) {
		this.payload.clientId = client.clientId;
		this.#client = client;
	}

	get client(): Client | undefined {
		return this.#client;
	}

	set resourceServer(resourceServer: ResourceServer) {
		this.setAudience(resourceServer.audience || resourceServer.identifier());
		this.#resourceServer = resourceServer;
	}

	get resourceServer(): ResourceServer | undefined {
		return this.#resourceServer;
	}

	stampsExpiryOnSave() {
		return false;
	}

	async save() {
		return super.save(this.remainingTTL);
	}

	/*
	 * A token kind with a configured lifetime (lib/configs/liveTime.ts `ttl`) overrides this to compute
	 * it; one without (registration and initial access tokens) lives as long as it was told to, or
	 * does not expire.
	 */
	get expiration(): number | undefined {
		return this.expiresIn;
	}

	get scopes() {
		return new Set(this.payload.scope?.split(' '));
	}

	get resourceIndicators() {
		return new Set(
			Array.isArray(this.payload.resource)
				? this.payload.resource
				: [this.payload.resource]
		);
	}

	setAudience(audience: string | string[]) {
		if (Array.isArray(audience)) {
			if (audience.length === 0) {
				return;
			}
			if (audience.length > 1) {
				throw new InvalidTarget('only a single audience value is supported');
			}
			[audience] = audience;
		} else if (typeof audience !== 'string' || !audience) {
			throw new InvalidTarget();
		}

		this.payload.aud = audience;
	}

	static async revokeByGrantId(grantId: string) {
		await this.adapter.revokeByGrantId(grantId);
	}

	static isSessionBound = false;
	// The model finder's own signature first, so the static side still extends BaseModel's.
	static async tryFind<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: ModelClass<A, T>,
		value: string,
		options?: { ignoreExpiration?: boolean }
	): Promise<T | undefined>;
	static async tryFind<A extends BaseTokenPayloadType, T extends BaseToken<A>>(
		this: TokenClass<A, T>,
		value: string,
		options?: { ignoreExpiration?: boolean; ignoreSessionBinding?: boolean }
	): Promise<T | undefined>;
	static async tryFind<A extends BaseTokenPayloadType, T extends BaseToken<A>>(
		this: TokenClass<A, T>,
		value: string,
		{ ignoreExpiration = false, ignoreSessionBinding = false } = {}
	): Promise<T | undefined> {
		const token = await super.tryFind<A, T>(value, {
			ignoreExpiration
		});
		if (
			this.isSessionBound === false ||
			!token?.payload.expiresWithSession ||
			ignoreSessionBinding
		) {
			return token;
		}
		if (!token.payload.sessionUid) {
			return;
		}

		const session = await Session.findByUid(token.payload.sessionUid);

		// related session was not found
		if (!session) {
			return;
		}

		// token and session principal are now different
		if (token.payload.accountId !== session.payload.accountId) {
			return;
		}

		// token and session grantId are now different
		if (token.payload.grantId !== session.grantIdFor(token.payload.clientId)) {
			return;
		}

		return token;
	}

	static async find<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: ModelClass<A, T> & Pick<typeof BaseModel, 'tryFind'>,
		value: string,
		options?: { ignoreExpiration?: boolean; error?: Error }
	): Promise<T>;
	static async find<A extends BaseTokenPayloadType, T extends BaseToken<A>>(
		this: TokenClass<A, T> & Pick<typeof BaseToken, 'tryFind'>,
		value: string,
		options?: {
			ignoreExpiration?: boolean;
			ignoreSessionBinding?: boolean;
			error?: Error;
		}
	): Promise<T>;
	static async find<A extends BaseTokenPayloadType, T extends BaseToken<A>>(
		this: TokenClass<A, T> & Pick<typeof BaseToken, 'tryFind'>,
		value: string,
		options?: {
			ignoreExpiration?: boolean;
			ignoreSessionBinding?: boolean;
			error?: Error;
		}
	): Promise<T> {
		const item = await this.tryFind<A, T>(value, options);
		if (!item) {
			throw options?.error || new this.notFoundError();
		}
		return item;
	}

	generateTokenId() {
		const format = this.resourceServer?.accessTokenFormat ?? 'opaque';
		if (format === 'opaque') {
			return super.generateTokenId();
		}
		if (format !== 'jwt') {
			throw new Error('invalid format resolved');
		}
		return jwt.generateTokenId.call(this);
	}

	async getValueAndPayload() {
		const format = this.resourceServer?.accessTokenFormat ?? 'opaque';
		const result = await super.getValueAndPayload();
		if (format === 'opaque') {
			return result;
		}
		if (format !== 'jwt') {
			throw new Error('invalid format resolved');
		}
		// Opaque always produces the payload; the JWT is built from it.
		if (!result.payload) {
			throw new Error('a token payload was not produced');
		}
		return jwt.getValueAndPayload.call(this, result.payload);
	}
}
