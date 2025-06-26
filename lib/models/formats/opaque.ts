import pickBy from '../../helpers/_/pick_by.ts';
import { assertPayload } from '../../helpers/jwt.ts';
import epochTime from '../../helpers/epoch_time.ts';
import instance from '../../helpers/weak_cache.ts';
import nanoid from '../../helpers/nanoid.ts';
import als from '../../helpers/als.ts';
import { provider } from 'lib/provider.js';
import { clockTolerance } from 'lib/configs/liveTime.js';

const withExtra = new Set(['AccessToken', 'ClientCredentials']);
const bitsPerSymbol = Math.log2(64);
const tokenLength = (i: number) => Math.ceil(i / bitsPerSymbol);

export class Opaque {
	generateTokenId() {
		let length;
		const { bitsOfOpaqueRandomness } = instance(provider).configuration.formats;
		if (typeof bitsOfOpaqueRandomness === 'function') {
			length = tokenLength(bitsOfOpaqueRandomness(this));
		} else {
			length = tokenLength(bitsOfOpaqueRandomness);
		}
		return nanoid(length);
	}
	async getValueAndPayload() {
		const { configuration } = instance(provider);
		const now = epochTime();
		const exp = this.exp || now + this.expiration;
		const payload = {
			iat: this.iat || epochTime(),
			...(exp ? { exp } : undefined),
			...pickBy(
				this,
				(val, key) =>
					this.constructor.IN_PAYLOAD.includes(key) &&
					typeof val !== 'undefined'
			)
		};

		if (withExtra.has(this.kind)) {
			// eslint-disable-next-line no-multi-assign
			payload.extra = this.extra = await configuration.extraTokenClaims(
				als.getStore(),
				this
			);
		}

		return { value: this.jti, payload };
	}
	static async verify(stored, { ignoreExpiration } = {}) {
		// checks that legacy tokens aren't accepted as opaque when their jti is passed
		if ('jwt' in stored || 'jwt-ietf' in stored || 'paseto' in stored)
			throw new TypeError();
		if ('format' in stored && stored.format !== 'opaque') throw new TypeError();

		assertPayload(stored, {
			ignoreExpiration,
			clockTolerance
		});

		return stored;
	}
}

export const opaque = {
	generateTokenId() {
		let length;
		const { bitsOfOpaqueRandomness } = instance(provider).configuration.formats;
		if (typeof bitsOfOpaqueRandomness === 'function') {
			length = tokenLength(bitsOfOpaqueRandomness(als.getStore(), this));
		} else {
			length = tokenLength(bitsOfOpaqueRandomness);
		}
		return nanoid(length);
	},
	async getValueAndPayload() {
		const { configuration } = instance(provider);
		const now = epochTime();
		const exp = this.exp || now + this.expiration;
		const payload = {
			iat: this.iat || now,
			...(exp ? { exp } : undefined),
			...pickBy(
				this,
				(val, key) =>
					this.constructor.IN_PAYLOAD.includes(key) &&
					typeof val !== 'undefined'
			)
		};

		if (withExtra.has(this.kind)) {
			// eslint-disable-next-line no-multi-assign
			payload.extra = this.extra = await configuration.extraTokenClaims(
				als.getStore(),
				this
			);
		}

		return { value: this.jti, payload };
	}
};
