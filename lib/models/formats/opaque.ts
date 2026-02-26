import pickBy from '../../helpers/_/pick_by.ts';
import { assertPayload } from '../../helpers/jwt.js';
import epochTime from '../../helpers/epoch_time.js';
import nanoid from '../../helpers/nanoid.js';
import {
	bitsOfOpaqueRandomness,
	clockTolerance
} from 'lib/configs/liveTime.js';

const bitsPerSymbol = Math.log2(64);
const tokenLength = (i: number) => Math.ceil(i / bitsPerSymbol);

export abstract class Opaque {
	declare expiration: number;
	declare iat: number;
	declare exp: number;
	declare jti: string;
	declare static IN_PAYLOAD: string[];

	generateTokenId(): string {
		const length = tokenLength(bitsOfOpaqueRandomness);
		return nanoid(length);
	}
	async getValueAndPayload() {
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
