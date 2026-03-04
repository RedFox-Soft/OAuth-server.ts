import { Type as t, type Static } from '@sinclair/typebox';
import als from '../helpers/als.ts';
import {
	BaseModel,
	BaseModelPayload,
	type BaseModelPayloadType
} from './base_model.js';
import { ttl } from '../configs/liveTime.js';
import { jwt } from './formats/jwt.js';
import { Session } from './session.js';
import { InvalidTarget } from 'lib/helpers/errors.js';

export const BaseTokenPayload = t.Composite([
	BaseModelPayload,
	t.Object({
		clientId: t.String(),

		// Properties below are required to be set by bound session for session bound tokens, but are optional to allow for non-session bound tokens to be used with the same model
		expiresWithSession: t.Optional(t.Boolean()),
		sessionUid: t.Optional(t.String()),
		accountId: t.Optional(t.String()),
		grantId: t.Optional(t.String()),

		// RFC 8707 Resource Indicators for OAuth 2.0 for Client-Credentional Grant and Access Tokens
		aud: t.Optional(t.String())
	})
]);

export type BaseTokenPayloadType = Static<typeof BaseTokenPayload>;

export class BaseToken<
	T extends BaseTokenPayloadType = BaseTokenPayloadType
> extends BaseModel<T> {
	model = BaseTokenPayload;
	#client;

	#resourceServer;

	constructor({ client, resourceServer, expiresIn, ...rest } = {}) {
		super(rest);
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

	set client(client) {
		this.payload.clientId = client.clientId;
		this.#client = client;
	}

	get client() {
		return this.#client;
	}

	set resourceServer(resourceServer) {
		this.setAudience(resourceServer.audience || resourceServer.identifier());
		this.#resourceServer = resourceServer;
	}

	get resourceServer() {
		return this.#resourceServer;
	}

	static expiresIn(...args) {
		if (this.name in ttl) {
			return ttl[this.name](...args);
		}
	}

	async save() {
		return super.save(this.remainingTTL);
	}

	get expiration() {
		if (!this.expiresIn) {
			this.expiresIn = this.constructor.expiresIn(
				als.getStore(),
				this,
				this.#client
			);
		}

		return this.expiresIn;
	}

	get scopes() {
		return new Set(this.payload.scope?.split(' '));
	}

	get resourceIndicators() {
		return new Set(
			Array.isArray(this.resource) ? this.resource : [this.resource]
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
	static async find<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: new (payload: A) => T,
		value: string,
		{ ignoreExpiration }?: { ignoreExpiration?: boolean | undefined }
	): Promise<T | undefined>;
	static async find<A extends BaseTokenPayloadType, T extends BaseToken<A>>(
		this: new (payload: A) => T,
		value: string,
		{ ignoreExpiration = false, ignoreSessionBinding = false } = {}
	): Promise<T | undefined> {
		const token = await super.find<A, T>(value, {
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
		return jwt.getValueAndPayload.call(this, result.payload);
	}
}
