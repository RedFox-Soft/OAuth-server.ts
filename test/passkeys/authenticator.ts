/*
 * A software passkey for the suite (specs/139 research R2): ES256 over WebCrypto, `none` attestation, CBOR through the
 * library's own `isoCBOR`, so nothing is added to the dependencies for it. Every input a browser or a device decides is
 * a parameter here — the origin, `crossOrigin` and `topOrigin` the browser writes into `clientDataJSON`, the flags and
 * the signature counter the device writes into `authenticatorData`, the user handle it hands back, the credential id
 * and the AAGUID — so a test can produce exactly the response a refusal is about. One instance per case: it holds the
 * private keys of the passkeys it made.
 */
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransport,
	RegistrationResponseJSON
} from '@simplewebauthn/server';
import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers';

const enc = new TextEncoder();

type Bytes = Uint8Array<ArrayBuffer>;

async function sha256(data: Bytes): Promise<Bytes> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function concat(...parts: Uint8Array[]): Bytes {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

function u32(n: number): Bytes {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, n);
	return bytes;
}

// WebCrypto signs ECDSA as raw r||s; WebAuthn carries an ES256 signature DER-encoded.
function rawToDer(raw: Bytes): Bytes {
	const integer = (x: Bytes) => {
		let i = 0;
		while (i < x.length - 1 && x[i] === 0) i++;
		let v: Bytes = x.slice(i);
		if ((v.at(0) ?? 0) & 0x80) v = concat(new Uint8Array([0]), v);
		return concat(new Uint8Array([0x02, v.length]), v);
	};
	const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
	return concat(new Uint8Array([0x30, body.length]), body);
}

/* User present, user verified, backup eligible ("can be synced"), backed up ("is synced"). */
export type Flags = { up?: boolean; uv?: boolean; be?: boolean; bs?: boolean };

function flagByte(flags: Flags, attested: boolean): number {
	return (
		(flags.up !== false ? 0x01 : 0) |
		(flags.uv !== false ? 0x04 : 0) |
		(flags.be ? 0x08 : 0) |
		(flags.bs ? 0x10 : 0) |
		(attested ? 0x40 : 0)
	);
}

/* What the browser writes into `clientDataJSON`: the page's origin, and whether it ran inside a frame of another. */
export type BrowserContext = {
	origin: string;
	crossOrigin?: boolean;
	topOrigin?: string;
};

function clientData(
	type: 'webauthn.create' | 'webauthn.get',
	challenge: string,
	browser: BrowserContext
): Bytes {
	return enc.encode(
		JSON.stringify({
			type,
			challenge,
			origin: browser.origin,
			crossOrigin: browser.crossOrigin ?? false,
			...(browser.topOrigin === undefined
				? {}
				: { topOrigin: browser.topOrigin })
		})
	);
}

type Held = {
	key: CryptoKeyPair;
	rpId: string;
	userHandle: string;
	count: number;
};

export type CreateChoices = {
	flags?: Flags;
	/* base64url; a fresh random 16-byte id when absent. */
	credentialId?: string;
	/* The RP ID the device scopes the passkey to; the options' `rp.id` when absent. */
	rpId?: string;
	transports?: AuthenticatorTransport[];
};

export type GetChoices = {
	flags?: Flags;
	/* Which passkey answers; the first one made for the options' RP ID when absent. */
	credentialId?: string;
	/* The user handle handed back; the one the passkey was made with when absent. */
	userHandle?: string;
	/* A counter written as is, instead of the passkey's own advancing by `countStep`. */
	counter?: number;
	/* The RP ID hashed into `authenticatorData`; the passkey's own when absent. */
	rpId?: string;
};

export class SoftAuthenticator {
	private readonly held = new Map<string, Held>();
	/* 16 bytes; all zero is what a device declaring nothing sends. */
	aaguid: Uint8Array = new Uint8Array(16);
	/* How much the signature counter advances per use; 0 for a device that never counts (many synced passkeys). */
	countStep = 1;

	async create(
		options: { challenge: string; rp: { id?: string }; user: { id: string } },
		browser: BrowserContext,
		choices: CreateChoices = {}
	): Promise<RegistrationResponseJSON> {
		const rpId = choices.rpId ?? options.rp.id;
		if (rpId === undefined) throw new Error('the options name no RP ID');
		const key = await crypto.subtle.generateKey(
			{ name: 'ECDSA', namedCurve: 'P-256' },
			true,
			['sign', 'verify']
		);
		const jwk = await crypto.subtle.exportKey('jwk', key.publicKey);
		if (jwk.x === undefined || jwk.y === undefined)
			throw new Error('an EC key without coordinates');
		const credentialBytes = choices.credentialId
			? isoBase64URL.toBuffer(choices.credentialId)
			: crypto.getRandomValues(new Uint8Array(16));
		const credentialId = isoBase64URL.fromBuffer(credentialBytes);
		this.held.set(credentialId, {
			key,
			rpId,
			userHandle: options.user.id,
			count: 0
		});

		const cose = new Map<number, number | Uint8Array>([
			[1, 2], // kty: EC2
			[3, -7], // alg: ES256
			[-1, 1], // crv: P-256
			[-2, isoBase64URL.toBuffer(jwk.x)],
			[-3, isoBase64URL.toBuffer(jwk.y)]
		]);
		const attested = concat(
			this.aaguid,
			new Uint8Array([
				credentialBytes.length >> 8,
				credentialBytes.length & 0xff
			]),
			credentialBytes,
			isoCBOR.encode(cose)
		);
		const authData = concat(
			await sha256(enc.encode(rpId)),
			new Uint8Array([flagByte(choices.flags ?? {}, true)]),
			u32(0),
			attested
		);
		const attestationObject = isoCBOR.encode(
			new Map<string, string | Uint8Array | Map<string, never>>([
				['fmt', 'none'],
				['attStmt', new Map<string, never>()],
				['authData', authData]
			])
		);
		return {
			id: credentialId,
			rawId: credentialId,
			type: 'public-key',
			clientExtensionResults: {},
			response: {
				clientDataJSON: isoBase64URL.fromBuffer(
					clientData('webauthn.create', options.challenge, browser)
				),
				attestationObject: isoBase64URL.fromBuffer(attestationObject),
				transports: choices.transports ?? ['internal']
			}
		};
	}

	async get(
		options: { challenge: string; rpId?: string },
		browser: BrowserContext,
		choices: GetChoices = {}
	): Promise<AuthenticationResponseJSON> {
		const credentialId =
			choices.credentialId ??
			[...this.held.entries()].find(
				([, held]) => held.rpId === options.rpId
			)?.[0];
		const held =
			credentialId === undefined ? undefined : this.held.get(credentialId);
		if (credentialId === undefined || held === undefined)
			throw new Error('no passkey for this RP ID');
		held.count += this.countStep;
		const authData = concat(
			await sha256(enc.encode(choices.rpId ?? held.rpId)),
			new Uint8Array([flagByte(choices.flags ?? {}, false)]),
			u32(choices.counter ?? held.count)
		);
		const clientDataJSON = clientData(
			'webauthn.get',
			options.challenge,
			browser
		);
		const signature = new Uint8Array(
			await crypto.subtle.sign(
				{ name: 'ECDSA', hash: 'SHA-256' },
				held.key.privateKey,
				concat(authData, await sha256(clientDataJSON))
			)
		);
		return {
			id: credentialId,
			rawId: credentialId,
			type: 'public-key',
			clientExtensionResults: {},
			response: {
				clientDataJSON: isoBase64URL.fromBuffer(clientDataJSON),
				authenticatorData: isoBase64URL.fromBuffer(authData),
				signature: isoBase64URL.fromBuffer(rawToDer(signature)),
				userHandle: choices.userHandle ?? held.userHandle
			}
		};
	}
}
