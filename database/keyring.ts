/*
 * bun run keyring new | add | write <kid> | remove <kid> | show
 *
 * Makes and changes the instance keyring (specs/116) outside the server: for an operator who keeps it in a
 * secrets manager, a Kubernetes Secret or a systemd credential rather than letting first-run setup write it.
 * Reads the current keyring from KEYRING, then the keyring file, then standard input; prints the new one on
 * standard output; never touches the database.
 *
 * A rotation is two runs and two deploys: `add` (the new key is readable everywhere before anything is
 * sealed with it), then `write <kid>` (new values are sealed with it, and the server moves old ones to it).
 * `remove` only once the console shows no value under that key and no kept backup was taken while it was in
 * use: restoring that backup needs it.
 */
import { existsSync, readFileSync } from 'node:fs';

import {
	effectiveKeyringPath,
	fingerprintOf,
	KeyringError,
	keyringDocument,
	newKey,
	newKeyId,
	newKeyringDocument,
	serializeKeyring,
	type KeyringDocument
} from '../lib/sealing/keyring.ts';

function fail(message: string): never {
	console.error(`keyring: ${message}`);
	process.exit(1);
}

async function current(): Promise<KeyringDocument> {
	const fromEnvironment = process.env.KEYRING?.trim();
	if (fromEnvironment) return keyringDocument(fromEnvironment);
	const path = effectiveKeyringPath();
	if (existsSync(path))
		return keyringDocument(readFileSync(path, 'utf8').trim());
	if (!process.stdin.isTTY) {
		const piped = (await Bun.stdin.text()).trim();
		if (piped) return keyringDocument(piped);
	}
	return fail(
		'no keyring to change: set KEYRING, point KEYRING_FILE at the keyring file, or pipe it in'
	);
}

async function main(command: string | undefined, argument: string | undefined) {
	switch (command) {
		case 'new':
			return serializeKeyring(newKeyringDocument());
		case 'add': {
			const keyring = await current();
			let kid = newKeyId();
			while (kid in keyring.keys) kid = newKeyId();
			return serializeKeyring({
				...keyring,
				keys: { ...keyring.keys, [kid]: newKey() }
			});
		}
		case 'write': {
			const keyring = await current();
			if (!argument || !(argument in keyring.keys)) {
				return fail(`"${argument ?? ''}" is not a key of this keyring`);
			}
			return serializeKeyring({ ...keyring, write: argument });
		}
		case 'remove': {
			const keyring = await current();
			if (!argument || !(argument in keyring.keys)) {
				return fail(`"${argument ?? ''}" is not a key of this keyring`);
			}
			if (argument === keyring.write) {
				return fail(
					'the write key cannot be removed; make another key the write key first'
				);
			}
			const keys = { ...keyring.keys };
			delete keys[argument];
			return serializeKeyring({ ...keyring, keys });
		}
		case 'show': {
			const keyring = await current();
			return Object.entries(keyring.keys)
				.map(
					([kid, key]) =>
						`${kid}${kid === keyring.write ? ' (write)' : ''}  fingerprint ${fingerprintOf(new Uint8Array(Buffer.from(key, 'base64url')))}`
				)
				.join('\n');
		}
		default:
			return fail(
				'usage: bun run keyring new | add | write <kid> | remove <kid> | show'
			);
	}
}

try {
	console.log(await main(process.argv[2], process.argv[3]));
} catch (error) {
	fail(
		error instanceof KeyringError
			? error.message
			: 'the keyring could not be read'
	);
}
