import { assertPayload } from '../../helpers/jwt.js';
import epochTime from '../../helpers/epoch_time.js';
import nanoid from '../../helpers/nanoid.js';
import {
	bitsOfOpaqueRandomness,
	clockTolerance
} from 'lib/configs/liveTime.js';
import { BaseModelPayload } from '../base_model.js';

const bitsPerSymbol = Math.log2(64);
const tokenLength = (i: number) => Math.ceil(i / bitsPerSymbol);

export abstract class Opaque {
	declare payload: BaseModelPayload;
	abstract get id(): string;

	get expiration() {
		if (typeof this.payload.exp === 'undefined') {
			throw new TypeError('expiration not set');
		}
		return this.payload.exp - epochTime();
	}

	generateTokenId(): string {
		const length = tokenLength(bitsOfOpaqueRandomness);
		return nanoid(length);
	}
	async getValueAndPayload(): Promise<{
		value: string;
		payload?: BaseModelPayload;
	}> {
		const now = epochTime();
		const payload = {
			iat: now,
			...this.payload
		};
		if (typeof payload.exp === 'undefined') {
			payload.exp = now + this.expiration;
		}

		return { value: this.id, payload };
	}
	static async verify(
		stored: Record<string, unknown>,
		{ ignoreExpiration = false } = {}
	) {
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
