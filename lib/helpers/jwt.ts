import {
	CompactEncrypt,
	CompactSign,
	compactDecrypt,
	compactVerify,
	decodeJwt,
	decodeProtectedHeader,
	errors
} from 'jose';

import { Type as t, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import * as base64url from './base64url.ts';
import epochTime from './epoch_time.ts';

const {
	JWEDecryptionFailed,
	JWKSNoMatchingKey,
	JWSSignatureVerificationFailed
} = errors;

export async function sign(payload, key, alg, options = {}) {
	const protectedHeader = {
		alg,
		typ: options.typ,
		...options.fields
	};
	const timestamp = epochTime();

	const iat = options.noIat ? undefined : timestamp;

	Object.assign(payload, {
		aud: options.audience !== undefined ? options.audience : payload.aud,
		exp:
			options.expiresIn !== undefined
				? timestamp + options.expiresIn
				: payload.exp,
		iat: payload.iat !== undefined ? payload.iat : iat,
		iss: options.issuer !== undefined ? options.issuer : payload.iss,
		sub: options.subject !== undefined ? options.subject : payload.sub
	});

	return new CompactSign(Buffer.from(JSON.stringify(payload)))
		.setProtectedHeader(protectedHeader)
		.sign(key);
}

export function decode(jwt: string): {
	header: Record<string, unknown>;
	payload: payloadType;
} {
	const { 0: protectedHeader, 1: payload, length } = jwt.split('.');
	if (length !== 3) {
		throw new TypeError('invalid JWT.decode input');
	}
	return {
		header: JSON.parse(base64url.decode(protectedHeader)),
		payload: JSON.parse(base64url.decode(payload))
	};
}

export function header(jwt: string): Record<string, unknown> {
	return JSON.parse(base64url.decode(jwt.split('.')[0]));
}

const jwtPayloadSchema = t.Object({
	nbf: t.Optional(t.Integer()),
	iat: t.Optional(t.Integer()),
	exp: t.Optional(t.Integer()),
	jti: t.Optional(t.String()),
	iss: t.Optional(t.String()),
	sub: t.Optional(t.String()),
	aud: t.Optional(t.Union([t.String(), t.Array(t.String())]))
});
type payloadType = Record<string, unknown> & Static<typeof jwtPayloadSchema>;

export function assertPayload(
	payload: payloadType,
	{
		clockTolerance = 0,
		audience,
		ignoreExpiration = false,
		issuer,
		subject = false
	}: {
		clockTolerance?: number;
		audience?: string;
		ignoreExpiration?: boolean;
		issuer?: string;
		subject?: boolean;
	} = {}
) {
	const timestamp = epochTime();

	if (Value.Check(jwtPayloadSchema, payload) === false) {
		const error = Value.Errors(jwtPayloadSchema, payload).First();
		throw new TypeError(
			`invalid jwt payload: ${error?.path} ${error?.message}`
		);
	}

	if (payload.nbf !== undefined && payload.nbf > timestamp + clockTolerance) {
		throw new Error('jwt not active yet');
	}
	if (
		payload.iat !== undefined &&
		payload.exp === undefined &&
		payload.iat > timestamp + clockTolerance
	) {
		throw new Error('jwt issued in the future');
	}
	if (
		payload.exp !== undefined &&
		!ignoreExpiration &&
		timestamp - clockTolerance >= payload.exp
	) {
		throw new Error('jwt expired');
	}
	if (subject && !payload.sub) {
		throw new Error('invalid sub value');
	}

	if (audience) {
		const aud = payload.aud;
		if (Array.isArray(aud)) {
			const match = aud.some((actual) => actual === audience);
			if (!match) throw new Error(`jwt audience missing ${audience}`);
		} else if (aud !== audience) {
			throw new Error(`jwt audience missing ${audience}`);
		}
	}

	if (issuer && payload.iss !== issuer) {
		throw new Error('jwt issuer invalid');
	}
}

export async function verify(jwt: string, keystore, options = {}) {
	let verified;
	let protectedHeader;
	try {
		protectedHeader = decodeProtectedHeader(jwt);

		const keys = keystore.selectForVerify({
			alg: protectedHeader.alg,
			kid: protectedHeader.kid
		});
		if (keys.length === 0) {
			throw new JWKSNoMatchingKey();
		} else {
			for (const key of keys) {
				try {
					verified = await compactVerify(
						jwt,
						await keystore.getKeyObject(key, true),
						{ algorithms: options.algorithm ? [options.algorithm] : undefined }
					);
				} catch {}
			}
		}

		if (!verified) {
			throw new JWSSignatureVerificationFailed();
		}
	} catch (err) {
		if (typeof keystore.fresh !== 'function' || keystore.fresh()) {
			throw err;
		}

		await keystore.refresh();
		return verify(jwt, keystore, options);
	}

	const payload = decodeJwt(jwt);
	assertPayload(payload, options);

	return { payload, header: protectedHeader };
}

export async function encrypt(cleartext, key, { enc, alg, fields } = {}) {
	const protectedHeader = {
		alg,
		enc,
		...fields
	};

	return new CompactEncrypt(Buffer.from(cleartext))
		.setProtectedHeader(protectedHeader)
		.encrypt(key);
}

export async function decrypt(jwe, keystore) {
	const protectedHeader = decodeProtectedHeader(jwe);

	const keys = keystore.selectForDecrypt({
		alg:
			protectedHeader.alg === 'dir' ? protectedHeader.enc : protectedHeader.alg,
		kid: protectedHeader.kid,
		epk: protectedHeader.epk
	});
	let decrypted;
	if (keys.length === 0) {
		throw new JWKSNoMatchingKey();
	} else {
		for (const key of keys) {
			try {
				decrypted = await compactDecrypt(jwe, keystore.getKeyObject(key));
			} catch {}
		}
	}

	if (!decrypted) {
		throw new JWEDecryptionFailed();
	}

	return Buffer.from(decrypted.plaintext);
}
