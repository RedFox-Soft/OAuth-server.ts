import {
	Type as t,
	type Static,
	type TObject,
	type TSchema
} from '@sinclair/typebox';
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

// A model class as its static finders use it: constructible from what its schema admits, with the
// statics they read.
export type ModelClass<A, T> = (new (payload: A) => T) & {
	schema: TSchema & { static: A };
} & Pick<typeof BaseModel, 'adapter' | 'verify' | 'notFoundError'>;

export class BaseModel<
	T extends BaseModelPayloadType = BaseModelPayloadType
> extends Opaque {
	/*
	 * The model's schema: the keys it persists, and what a stored record must satisfy to become one
	 * (`fromStored`). Static, so a finder can check a record before any instance exists; every subclass
	 * names its own.
	 */
	static schema: TObject = BaseModelPayload;
	declare ['constructor']: typeof BaseModel;
	payload = {} as Req<T, 'kind'>;

	get model(): TObject {
		return this.constructor.schema;
	}

	constructor(payload: Partial<T> = {}) {
		super();

		payload.kind ||= this.constructor.name;
		/*
		 * The base members only. A payload under construction is partial by design — a token takes its
		 * clientId from the client after this runs — so the model's own schema is checked where a
		 * record is complete: on the way out of storage, in `fromStored`.
		 */
		if (!Value.Check(BaseModelPayload, payload)) {
			throw new TypeError('invalid payload');
		}
		// Taken as the full payload: a caller built it, or `fromStored` checked it against the schema.
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

	/*
	 * A stored record as this model, or undefined when it is not one. Its schema is checked here because
	 * nothing else checks it: save filters top-level keys only, and the constructor runs before the
	 * model's own fields exist. A record the schema refuses is treated as not found.
	 */
	static async fromStored<
		A extends BaseModelPayloadType,
		T extends BaseModel<A>
	>(
		this: ModelClass<A, T>,
		stored: Record<string, unknown>,
		{ ignoreExpiration = false } = {}
	): Promise<T | undefined> {
		try {
			const payload = await this.verify(stored, { ignoreExpiration });
			return Value.Check(this.schema, payload) ? new this(payload) : undefined;
		} catch {
			return;
		}
	}

	static async tryFind<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: ModelClass<A, T> & Pick<typeof BaseModel, 'fromStored'>,
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

		return this.fromStored<A, T>(stored, { ignoreExpiration });
	}

	static async find<A extends BaseModelPayloadType, T extends BaseModel<A>>(
		this: ModelClass<A, T> & Pick<typeof BaseModel, 'tryFind' | 'fromStored'>,
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
