import snakeCase from '../helpers/_/snake_case.ts';
import epochTime from '../helpers/epoch_time.ts';
import pickBy from '../helpers/_/pick_by.ts';
import { Opaque } from './formats/opaque.js';
import { provider } from 'lib/provider.js';
import { adapter } from 'lib/adapters/index.js';

const IN_PAYLOAD = ['iat', 'exp', 'jti', 'kind'];

export class BaseModel extends Opaque {
	constructor({ jti, kind, ...payload } = {}) {
		super();
		Object.assign(
			this,
			pickBy(payload, (val, key) => this.constructor.IN_PAYLOAD.includes(key))
		);

		if (kind && kind !== this.constructor.name) {
			throw new TypeError('kind mismatch');
		}

		this.kind = kind || this.constructor.name;
		this.jti = jti;
	}

	static instantiate(payload) {
		return new this(payload);
	}

	async save(ttl) {
		if (!this.jti) {
			this.jti = this.generateTokenId();
		}

		// this is true for all BaseToken descendants
		if (typeof this.constructor.expiresIn !== 'function') {
			this.exp = epochTime() + ttl;
		}

		const { value, payload } = await this.getValueAndPayload();

		if (payload) {
			await this.adapter.upsert(this.jti, payload, ttl);
			this.emit('saved');
		} else {
			this.emit('issued');
		}

		return value;
	}

	async destroy() {
		await this.adapter.destroy(this.jti);
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

	static async find(value: string, { ignoreExpiration = false } = {}) {
		if (typeof value !== 'string') {
			return;
		}

		const stored = await this.adapter.find(value);
		if (!stored) {
			return;
		}

		try {
			const payload = await this.verify(stored, { ignoreExpiration });

			return this.instantiate(payload);
		} catch (err) {
			return;
		}
	}

	emit(eventName: string) {
		provider.emit(`${snakeCase(this.kind)}.${eventName}`, this);
	}

	/*
	 * ttlPercentagePassed
	 * returns a Number (0 to 100) with the value being percentage of the token's ttl already
	 * passed. The higher the percentage the older the token is. At 0 the token is fresh, at a 100
	 * it is expired.
	 */
	ttlPercentagePassed() {
		const now = epochTime();
		const percentage = Math.floor(
			100 * ((now - this.iat) / (this.exp - this.iat))
		);
		return Math.max(Math.min(100, percentage), 0);
	}

	get isValid() {
		return !this.isExpired;
	}

	get isExpired() {
		return this.exp <= epochTime();
	}

	get remainingTTL() {
		if (!this.exp) {
			return this.expiration;
		}
		return this.exp - epochTime();
	}
}
