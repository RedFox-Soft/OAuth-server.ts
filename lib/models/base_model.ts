import { Type as t, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import snakeCase from '../helpers/_/snake_case.js';
import epochTime from '../helpers/epoch_time.js';
import { Opaque } from './formats/opaque.js';
import { provider } from 'lib/provider.js';
import { adapter } from 'lib/adapters/index.js';

const IN_PAYLOAD = ['iat', 'exp', 'jti', 'kind'];

export const BaseModelPayload = t.Object({
	jti: t.Optional(t.String()),
	kind: t.Optional(t.String()),
	exp: t.Optional(t.Number()),
	iat: t.Optional(t.Number())
});

export type BaseModelPayloadType = Static<typeof BaseModelPayload>;

export class BaseModel<
	T extends BaseModelPayloadType = BaseModelPayloadType
> extends Opaque {
	model = BaseModelPayload;
	payload = {} as T;

	constructor(payload: T = {} as T) {
		super();

		const check = Value.Check(this.model, payload);
		if (!check) {
			throw new TypeError('invalid payload');
		}
		this.payload = payload;
		const { kind } = payload;
		if (kind && kind !== this.constructor.name) {
			throw new TypeError('kind mismatch');
		}
		payload.kind = kind || this.constructor.name;
	}

	async save(ttl: number) {
		// this is true for all BaseToken descendants
		if (typeof this.constructor.expiresIn !== 'function') {
			this.payload.exp = epochTime() + ttl;
		}

		const jti = this.id;
		const { value, payload } = await this.getValueAndPayload();

		if (payload) {
			await this.adapter.upsert(jti, payload, ttl);
			this.emit('saved');
		} else {
			this.emit('issued');
		}

		return value;
	}

	get id() {
		if (typeof this.payload.jti === 'undefined') {
			this.payload.jti = this.generateTokenId();
		}
		return this.payload.jti;
	}

	set id(value) {
		this.payload.jti = value;
	}

	async destroy() {
		if (!this.id) {
			return;
		}
		await this.adapter.destroy(this.id);
		this.emit('destroyed');
	}

	static get adapter() {
		return adapter(this.name);
	}

	get adapter() {
		return adapter(this.constructor.name);
	}

	static get IN_PAYLOAD() {
		return IN_PAYLOAD;
	}

	static async find<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: new (payload: A) => T,
		value: string,
		{ ignoreExpiration = false } = {}
	): Promise<T | undefined> {
		if (typeof value !== 'string') {
			return;
		}

		const stored = await this.adapter.find(value);
		if (!stored) {
			return;
		}

		try {
			const payload = await this.verify(stored, { ignoreExpiration });

			return new this(payload);
		} catch (err) {
			return;
		}
	}

	emit(eventName: string) {
		const kind = this.constructor.name;
		provider.emit(`${snakeCase(kind)}.${eventName}`, this);
	}

	/*
	 * ttlPercentagePassed
	 * returns a Number (0 to 100) with the value being percentage of the token's ttl already
	 * passed. The higher the percentage the older the token is. At 0 the token is fresh, at a 100
	 * it is expired.
	 */
	ttlPercentagePassed() {
		const now = epochTime();
		const { iat, exp } = this.payload;
		const percentage = Math.floor(100 * ((now - iat) / (exp - iat)));
		return Math.max(Math.min(100, percentage), 0);
	}

	get isValid() {
		return !this.isExpired;
	}

	get isExpired() {
		const { exp } = this.payload;
		return exp <= epochTime();
	}

	get remainingTTL() {
		const { exp } = this.payload;
		if (!exp) {
			return this.expiration;
		}
		return exp - epochTime();
	}
}
