import { CompactEncrypt, compactDecrypt, decodeProtectedHeader } from 'jose';

import { activeKeyring } from './keyring.js';

/*
 * A sealed value is `fxsealed.` followed by a JWE in compact serialisation: `dir` + `A256GCM`, so AES-256-GCM
 * with a fresh IV per value, under the keyring's write key. The protected header names the key (`kid`) and
 * binds the value to its record and field (`bnd`); GCM authenticates that header, so a value copied into
 * another record keeps its binding and does not open there.
 *
 * The prefix is what tells a sealed value from plaintext during an upgrade, without parsing: no stored
 * plaintext secret begins with it (specs/116 research R3).
 */
export const SEALED_PREFIX = 'fxsealed.';
const PREFIX_BYTES = Buffer.from(SEALED_PREFIX, 'utf8');

export type OpenFailure = 'missing-key' | 'integrity' | 'binding';

export type Opened<T> =
	| { ok: true; value: T; kid: string }
	| { ok: false; reason: OpenFailure; kid?: string };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function isSealed(stored: unknown): boolean {
	if (typeof stored === 'string') return stored.startsWith(SEALED_PREFIX);
	if (stored instanceof Uint8Array) {
		return (
			stored.length > PREFIX_BYTES.length &&
			Buffer.from(stored.subarray(0, PREFIX_BYTES.length)).equals(PREFIX_BYTES)
		);
	}
	return false;
}

function sealedText(stored: string | Uint8Array): string {
	return typeof stored === 'string' ? stored : decoder.decode(stored);
}

/* The key id a sealed value names, read from its header without decrypting; undefined for plaintext. */
export function kidOf(stored: unknown): string | undefined {
	if (!isSealed(stored)) return undefined;
	try {
		const header = decodeProtectedHeader(
			sealedText(stored as string | Uint8Array).slice(SEALED_PREFIX.length)
		);
		return typeof header.kid === 'string' ? header.kid : undefined;
	} catch {
		return undefined;
	}
}

/* Seals with the write key. Throws when no keyring is in use: a caller that seals has checked for one. */
export async function seal(
	plain: string | Uint8Array,
	binding: string
): Promise<string> {
	const keyring = activeKeyring();
	if (!keyring) throw new Error('no keyring is in use');
	const key = keyring.keys.get(keyring.write);
	if (!key) throw new Error('the keyring has no write key');
	const bytes = typeof plain === 'string' ? encoder.encode(plain) : plain;
	const jwe = await new CompactEncrypt(bytes)
		.setProtectedHeader({
			alg: 'dir',
			enc: 'A256GCM',
			kid: keyring.write,
			bnd: binding
		})
		.encrypt(key);
	return SEALED_PREFIX + jwe;
}

export async function sealBytes(
	plain: Uint8Array,
	binding: string
): Promise<Buffer> {
	return Buffer.from(await seal(plain, binding), 'utf8');
}

async function openRaw(
	stored: string | Uint8Array,
	binding: string
): Promise<Opened<Uint8Array>> {
	const jwe = sealedText(stored).slice(SEALED_PREFIX.length);
	let kid: string | undefined;
	try {
		const header = decodeProtectedHeader(jwe);
		kid = typeof header.kid === 'string' ? header.kid : undefined;
	} catch {
		return { ok: false, reason: 'integrity' };
	}
	const key = kid === undefined ? undefined : activeKeyring()?.keys.get(kid);
	if (!kid || !key) return { ok: false, reason: 'missing-key', kid };
	try {
		const { plaintext, protectedHeader } = await compactDecrypt(jwe, key, {
			keyManagementAlgorithms: ['dir'],
			contentEncryptionAlgorithms: ['A256GCM']
		});
		if (protectedHeader.bnd !== binding) {
			return { ok: false, reason: 'binding', kid };
		}
		return { ok: true, value: plaintext, kid };
	} catch {
		return { ok: false, reason: 'integrity', kid };
	}
}

export async function openText(
	stored: string,
	binding: string
): Promise<Opened<string>> {
	const opened = await openRaw(stored, binding);
	return opened.ok
		? { ...opened, value: decoder.decode(opened.value) }
		: opened;
}

export async function openBytes(
	stored: Uint8Array,
	binding: string
): Promise<Opened<Buffer>> {
	const opened = await openRaw(stored, binding);
	return opened.ok ? { ...opened, value: Buffer.from(opened.value) } : opened;
}
