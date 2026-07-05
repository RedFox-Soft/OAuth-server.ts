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
		const ctor = this.constructor as unknown as {
			filterStoredPayload?: boolean;
		};

		// Token models derive their storage contract from their TypeBox schema (this.model):
		// only fields declared in the schema are persisted and instance-only fields are transient.
		// Non-token models (Session, Grant, Interaction, …) keep storing their whole payload.
		if (!ctor.filterStoredPayload) {
			const payload = {
				iat: now,
				...this.payload
			};
			if (typeof payload.exp === 'undefined') {
				payload.exp = now + this.expiration;
			}
			return { value: this.id, payload };
		}

		// Intentionally a SHALLOW, top-level filter — do NOT replace with Value.Clean().
		// Value.Clean recurses into nested object schemas and prunes their contents, and several
		// persisted fields are deliberately freeform (claims: t.Object({}), rar: t.Array(t.Object({})),
		// …). Clean would strip those down to {} and silently drop id_token/userinfo claims. We
		// select the schema's top-level keys and copy each value verbatim so nested content is kept.
		// Undefined values are omitted so absent optionals don't appear in storage.
		const model = (
			this as unknown as { model: { properties: Record<string, unknown> } }
		).model;
		const source = this.payload as Record<string, unknown>;
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
			payload.exp = now + this.expiration;
		}

		return { value: this.id, payload: payload as BaseModelPayload };
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
