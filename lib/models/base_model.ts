import { Type as t, type Static, type TObject } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import snakeCase from '../helpers/_/snake_case.js';
import epochTime from '../helpers/epoch_time.js';
import { Opaque } from './formats/opaque.js';
import { eventBus } from 'lib/event_bus.js';
import { adapter } from 'lib/adapters/index.js';
import { InvalidToken } from 'lib/helpers/errors.js';

export const BaseModelPayload = t.Object({
	jti: t.Optional(t.String()),
	kind: t.Optional(t.String()),
	exp: t.Optional(t.Number()),
	iat: t.Optional(t.Number())
});

export type BaseModelPayloadType = Static<typeof BaseModelPayload>;
type Req<T, K extends keyof T> = Required<Pick<T, K>> & Omit<T, K>;

// A model class as its static finders use it: constructible from a stored payload, with the statics
// they read.
export type ModelClass<A, T> = (new (payload: A) => T) &
	Pick<typeof BaseModel, 'adapter' | 'verify' | 'notFoundError'>;

export class BaseModel<
	T extends BaseModelPayloadType = BaseModelPayloadType
> extends Opaque {
	// Widened: every subclass names its own schema here.
	model: TObject = BaseModelPayload;
	payload = {} as Req<T, 'kind'>;

	constructor(payload: Partial<T> = {}) {
		super();

		payload.kind ||= this.constructor.name;
		const check = Value.Check(this.model, payload);
		if (!check) {
			throw new TypeError('invalid payload');
		}
		// Taken as the full payload: a caller built it or storage returned it. Not a verified narrowing —
		// the check above runs against BaseModelPayload only (wiki: token-payload-access-contract).
		this.payload = payload as Req<T, 'kind'>;
		const { kind } = payload;
		if (kind && kind !== this.constructor.name) {
			throw new TypeError('kind mismatch');
		}
	}

	/*
	 * Whether save() stamps `exp` from the TTL it is given. A token answers false: it computes its own
	 * expiry from its lifetime when its payload is produced (Opaque.getValueAndPayload).
	 */
	stampsExpiryOnSave(): boolean {
		return true;
	}

	async save(ttl: number | undefined) {
		if (this.stampsExpiryOnSave() && ttl !== undefined) {
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

	get id(): string {
		this.payload.jti ??= this.generateTokenId();
		return this.payload.jti;
	}

	get jti() {
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

	// Default error thrown by the strict `find` on miss; overridable per model.
	// `never[]` (not `any[]`) keeps this Principle-IV clean while accepting any
	// zero/optional-arg OIDCProviderError subclass.
	static notFoundError: new (...args: never[]) => Error = InvalidToken;

	static async tryFind<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: ModelClass<A, T>,
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

	static async find<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: ModelClass<A, T> & Pick<typeof BaseModel, 'tryFind'>,
		value: string,
		options?: { ignoreExpiration?: boolean; error?: Error }
	): Promise<T> {
		const item = await this.tryFind<A, T>(value, options);
		if (!item) {
			throw options?.error || new this.notFoundError();
		}
		return item;
	}

	emit(eventName: string) {
		const kind = this.constructor.name;
		eventBus.emit(`${snakeCase(kind)}.${eventName}`, this);
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
		// A lifetime it cannot know is reported as fresh.
		if (iat === undefined || exp === undefined) {
			return 0;
		}
		const percentage = Math.floor(100 * ((now - iat) / (exp - iat)));
		return Math.max(Math.min(100, percentage), 0);
	}

	get isValid() {
		return !this.isExpired;
	}

	get isExpired() {
		const { exp } = this.payload;
		return exp !== undefined && exp <= epochTime();
	}

	get remainingTTL() {
		const { exp } = this.payload;
		if (!exp) {
			return this.expiration;
		}
		return exp - epochTime();
	}
}
