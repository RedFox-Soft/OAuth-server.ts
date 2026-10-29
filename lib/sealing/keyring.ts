import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

/*
 * The instance keyring (specs/116): the keys stored secrets are sealed with. A deployment secret of the same
 * kind as the database connection string, so it never comes from the database it protects, nor from a setting
 * (which lives there). It arrives once, at import, from `KEYRING` or from a keyring file, or later from the
 * first-run setup or the console, which generate one and put it to use (generate.ts).
 *
 * `write` names the key new values are sealed with; every other key is read but never written with. That is
 * all a two-step rotation needs: add a key, roll it out to every process, then point `write` at it.
 */

export interface KeyringDocument {
	v: 1;
	write: string;
	keys: Record<string, string>;
}

export type KeyringSource = 'environment' | 'file';

export interface ActiveKeyring {
	write: string;
	keys: ReadonlyMap<string, Uint8Array>;
	source: KeyringSource;
}

export class KeyringError extends Error {}

export const KEY_ID_PATTERN = /^\d{8}-[A-Za-z0-9_-]{4}$/;
export const DEFAULT_KEYRING_FILE = 'keyring/foxauth.keyring';
const KEY_BYTES = 32;

/*
 * Every reason a keyring is refused names what is wrong and never echoes a key: the message reaches a startup
 * log, and a key that reached a log is a key to rotate.
 */
export function keyringDocument(text: string): KeyringDocument {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new KeyringError('the keyring is not JSON');
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		throw new KeyringError('the keyring is not a JSON object');
	}
	const { v, write, keys } = parsed as Record<string, unknown>;
	if (v !== 1) throw new KeyringError('the keyring\'s "v" must be 1');
	if (typeof keys !== 'object' || keys === null || Array.isArray(keys)) {
		throw new KeyringError('the keyring\'s "keys" must be an object');
	}
	const entries = Object.entries(keys);
	if (entries.length === 0) {
		throw new KeyringError('the keyring holds no key');
	}
	for (const [kid, value] of entries) {
		if (!KEY_ID_PATTERN.test(kid)) {
			throw new KeyringError(
				`the key id "${kid}" is not of the form YYYYMMDD-xxxx`
			);
		}
		if (typeof value !== 'string' || keyBytes(value) === null) {
			throw new KeyringError(
				`the key "${kid}" is not ${KEY_BYTES} bytes of base64url`
			);
		}
	}
	if (typeof write !== 'string' || !(write in keys)) {
		throw new KeyringError('the keyring\'s "write" must name one of its keys');
	}
	return {
		v: 1,
		write,
		keys: Object.fromEntries(entries)
	};
}

function keyBytes(value: string): Uint8Array | null {
	const bytes = Buffer.from(value, 'base64url');
	if (bytes.length !== KEY_BYTES) return null;
	// Buffer decodes leniently; a value that does not survive the round trip is not what the operator meant.
	if (bytes.toString('base64url') !== value.replace(/=+$/, '')) return null;
	return new Uint8Array(bytes);
}

export function newKeyId(at: Date = new Date()): string {
	const day = at.toISOString().slice(0, 10).replaceAll('-', '');
	return `${day}-${randomBytes(3).toString('base64url')}`;
}

export function newKey(): string {
	return randomBytes(KEY_BYTES).toString('base64url');
}

export function newKeyringDocument(at: Date = new Date()): KeyringDocument {
	const kid = newKeyId(at);
	return { v: 1, write: kid, keys: { [kid]: newKey() } };
}

export function serializeKeyring(document: KeyringDocument): string {
	return JSON.stringify(document);
}

function activeFrom(
	document: KeyringDocument,
	source: KeyringSource
): ActiveKeyring {
	const keys = new Map<string, Uint8Array>();
	for (const [kid, value] of Object.entries(document.keys)) {
		const bytes = keyBytes(value);
		if (bytes) keys.set(kid, bytes);
	}
	return { write: document.write, keys, source };
}

/* Resolved against the working directory: `/app/keyring/foxauth.keyring` in the image. */
export function effectiveKeyringPath(): string {
	const named = process.env.KEYRING_FILE?.trim();
	if (named) return resolve(process.cwd(), named);
	/*
	 * Under test, a directory nobody creates: a spec that generates a keyring without naming where must never
	 * write one into a developer's working copy.
	 */
	if (process.env.NODE_ENV === 'test') {
		return resolve(
			tmpdir(),
			'foxauth-keyring-not-configured',
			'foxauth.keyring'
		);
	}
	return resolve(process.cwd(), DEFAULT_KEYRING_FILE);
}

function loadAtImport(): ActiveKeyring | null {
	/*
	 * The suite's keyring is set by test_helper.ts and nothing else, so a developer's `.env` or a keyring file
	 * left by a local first-run never reaches it, as the datastore variables never reach a hermetic script.
	 */
	if (process.env.NODE_ENV === 'test') return null;
	const fromEnvironment = process.env.KEYRING?.trim() || undefined;
	const path = effectiveKeyringPath();
	const fileExists = existsSync(path);
	if (fromEnvironment && fileExists) {
		throw new KeyringError(
			`KEYRING is set and a keyring file exists at ${path}, and a deployment supplies its keyring exactly one way. Remove whichever does not belong to this deployment and start again — checking .env and .env.local as well as the shell, since those are loaded automatically.`
		);
	}
	if (fromEnvironment) {
		return activeFrom(keyringDocument(fromEnvironment), 'environment');
	}
	if (fileExists) {
		let text: string;
		try {
			text = readFileSync(path, 'utf8');
		} catch {
			throw new KeyringError(`the keyring file at ${path} cannot be read`);
		}
		return activeFrom(keyringDocument(text.trim()), 'file');
	}
	return null;
}

let active: ActiveKeyring | null = loadAtImport();
const listeners = new Set<() => void>();

export function activeKeyring(): ActiveKeyring | null {
	return active;
}

export function keyringSource(): KeyringSource | null {
	return active?.source ?? null;
}

/* Puts a keyring generated by the first-run setup or the console to use in this process, without a restart. */
export function activate(document: KeyringDocument, source: KeyringSource) {
	active = activeFrom(keyringDocument(serializeKeyring(document)), source);
	for (const listener of listeners) listener();
}

/* Called whenever the keyring in use changes, so a check made against the previous one is made again. */
export function onKeyringChanged(listener: () => void): void {
	listeners.add(listener);
}

/* Test-only, like `resetOriginSalt`: the keyring a spec file runs under, or none. */
export function resetKeyringForTests(
	document: KeyringDocument | null,
	source: KeyringSource = 'environment'
) {
	active = document ? activeFrom(document, source) : null;
	for (const listener of listeners) listener();
}

/*
 * Confirms key material without revealing it: the database keeps one per key id, so a keyring that reuses an
 * id with different bytes is refused at startup instead of sealing values the right key cannot open.
 */
export function fingerprintOf(key: Uint8Array): string {
	return createHmac('sha256', key)
		.update('foxauth keyring fingerprint v1')
		.digest()
		.subarray(0, 16)
		.toString('base64url');
}
