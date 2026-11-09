/*
 * Ed25519 verification of FoxTrust's publication (specs/125): a detached 64-byte signature over the exact bytes, made
 * with a key this release pins. The keys arrive as an argument so a test can sign with a key of its own; in the server
 * they are always ATTACKER_LIST_KEYS.
 */

const imported = new Map<string, Promise<CryptoKey | null>>();

function keyOf(raw: string): Promise<CryptoKey | null> {
	let key = imported.get(raw);
	if (!key) {
		key = crypto.subtle
			.importKey(
				'raw',
				Buffer.from(raw, 'base64'),
				{ name: 'Ed25519' },
				false,
				['verify']
			)
			.catch(() => null);
		imported.set(raw, key);
	}
	return key;
}

/* True when one of `keys` signed `data`; false for anything else, including a malformed key or signature. */
export async function verifySignature(
	data: Uint8Array<ArrayBuffer>,
	signature: Uint8Array<ArrayBuffer>,
	keys: Readonly<Record<string, string>>
): Promise<boolean> {
	if (signature.length !== 64) return false;
	for (const raw of Object.values(keys)) {
		const key = await keyOf(raw);
		if (!key) continue;
		try {
			if (await crypto.subtle.verify('Ed25519', key, signature, data)) {
				return true;
			}
		} catch {
			// A key or signature the runtime refuses to use is a signature that did not verify.
		}
	}
	return false;
}
