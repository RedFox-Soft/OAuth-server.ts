import crypto, { type KeyObject } from 'node:crypto';

import { instanceSigningKeyStore } from '../adapters/index.js';
import { SIGNED_PREFIX } from '../consts/address_lookup.js';

export type InstanceKey =
	| { readable: true; privateKey: KeyObject; publicKey: string }
	| { readable: false };

function fromStored(stored: unknown): InstanceKey {
	/*
	 * Zero bytes is how the sealing decorator answers a value it cannot open (no keyring, or another one). That is
	 * reported and never repaired: FoxTrust binds this instance's id to its first pair for good (SI-6), so a new pair
	 * would only earn "key mismatch" until FoxTrust's operator releases the id.
	 */
	if (!(stored instanceof Uint8Array) || stored.length === 0) {
		return { readable: false };
	}
	try {
		const privateKey = crypto.createPrivateKey({
			key: Buffer.from(stored),
			format: 'der',
			type: 'pkcs8'
		});
		if (privateKey.asymmetricKeyType !== 'ed25519') return { readable: false };
		const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
		if (typeof jwk.x !== 'string') return { readable: false };
		return { readable: true, privateKey, publicKey: jwk.x };
	} catch {
		return { readable: false };
	}
}

/*
 * This instance's Ed25519 key pair (specs/136 research R2), created the first time it is asked for. The private half
 * is a sealed singleton secret; `create` writes only when there is none and answers what is stored, so processes
 * racing on the first use all adopt one pair. There is no path here, or anywhere, that replaces it.
 */
export async function instanceKey(): Promise<InstanceKey> {
	const stored = await instanceSigningKeyStore.read();
	if (stored !== null && stored !== undefined) return fromStored(stored);
	const { privateKey } = crypto.generateKeyPairSync('ed25519');
	const der = privateKey.export({ format: 'der', type: 'pkcs8' });
	return fromStored(await instanceSigningKeyStore.create(der));
}

/* The public half, as the usage report and the registration carry it: 43 base64url characters, or null. */
export async function instancePublicKey(): Promise<string | null> {
	try {
		const key = await instanceKey();
		return key.readable ? key.publicKey : null;
	} catch {
		return null;
	}
}

export interface SignedFields {
	instanceId: string;
	instanceKey: string;
	issuedAt: string;
	nonce: string;
}

/*
 * The registration's signature: Ed25519 over exactly the bytes FoxTrust's contract names, each value as sent. The
 * private key leaves this function only as the signature it makes (SI-1).
 */
export function signRegistration(
	privateKey: KeyObject,
	fields: SignedFields
): string {
	const bytes = Buffer.from(
		[
			SIGNED_PREFIX,
			fields.instanceId,
			fields.instanceKey,
			fields.issuedAt,
			fields.nonce
		].join('\n'),
		'utf8'
	);
	return crypto.sign(null, bytes, privateKey).toString('base64url');
}
