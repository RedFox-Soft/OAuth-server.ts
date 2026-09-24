import { assertPayload } from '../../helpers/jwt.js';
import epochTime from '../../helpers/epoch_time.js';
import nanoid from '../../helpers/nanoid.js';
import {
	bitsOfOpaqueRandomness,
	clockTolerance
} from 'lib/configs/liveTime.js';
import type { TObject } from '@sinclair/typebox';
import { type BaseModelPayloadType } from '../base_model.js';

const bitsPerSymbol = Math.log2(64);
const tokenLength = (i: number) => Math.ceil(i / bitsPerSymbol);

export abstract class Opaque {
	declare payload: BaseModelPayloadType;
	// The model's TypeBox schema: what it persists (see getValueAndPayload).
	declare model: TObject;
	abstract get id(): string;

	// Seconds left; a token without a configured lifetime overrides this to answer undefined.
	get expiration(): number | undefined {
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
		payload?: Record<string, unknown>;
	}> {
		const now = epochTime();

		// Every persisted model derives its storage contract from its TypeBox schema (this.model):
		// only fields declared in the schema are persisted; instance-only fields are transient.
		//
		// Intentionally a SHALLOW, top-level filter — do NOT replace with Value.Clean().
		// Value.Clean recurses into nested object schemas and prunes their contents, and several
		// persisted fields are deliberately freeform (claims: t.Object({}), rar: t.Array(t.Object({})),
		// …). Clean would strip those down to {} and silently drop id_token/userinfo claims. We
		// select the schema's top-level keys and copy each value verbatim so nested content is kept.
		// Undefined values are omitted so absent optionals don't appear in storage.
		const { model } = this;
		const source: Record<string, unknown> = this.payload;
		const payload: Record<string, unknown> = {};
		for (const key of Object.keys(model.properties)) {
			if (source[key] !== undefined) {
				payload[key] = source[key];
			}
		}
		if (payload.iat === undefined) {
			payload.iat = now;
		}
		if (payload.exp === undefined) {
			// Non-expiring tokens (RegistrationAccessToken / InitialAccessToken with no
			// configured TTL) have an undefined expiration; leave `exp` absent rather than
			// writing `now + undefined` (NaN), which would fail the integer payload check on
			// the next verify. Tokens with a finite TTL keep their computed expiry.
			const expiration = this.expiration;
			if (expiration !== undefined && Number.isFinite(expiration)) {
				payload.exp = now + expiration;
			}
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
