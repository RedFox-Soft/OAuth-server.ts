import { closeSync, openSync, writeSync } from 'node:fs';

import { getKeyringStateStore } from '../adapters/index.js';
import {
	activate,
	effectiveKeyringPath,
	newKeyringDocument,
	serializeKeyring
} from './keyring.js';
import { keyringChecked } from './startup.js';
import { startPassSoon } from './pass.js';

/*
 * A new keyring, made by the first-run setup or by the console, and put where it can be used (specs/116
 * research R6). Never made silently at startup: a key generated inside a container that is then recreated is
 * gone, and every value sealed under it with it.
 */

export interface Placement {
	keyring: string;
	applied: boolean;
	location?: string;
}

/*
 * Written only into a directory that already exists: the server cannot tell a mounted volume from a
 * container's own writable layer, and a directory the operator created or mounted is the one signal that the
 * place survives a restart. The open alone decides, with no check before it that the answer could change
 * after: it never creates the directory, and `wx` fails rather than replace a keyring already there.
 */
function writtenToFile(serialized: string): string | null {
	const path = effectiveKeyringPath();
	let descriptor: number | undefined;
	try {
		descriptor = openSync(path, 'wx', 0o600);
		writeSync(descriptor, serialized + '\n');
		return path;
	} catch {
		// Not the reason, which could quote the path's contents on some platforms; the caller shows the keyring instead.
		return null;
	} finally {
		if (descriptor !== undefined) closeSync(descriptor);
	}
}

/*
 * Generates a keyring and, where a keyring file can be written, puts it to use at once and starts sealing
 * what is already stored. Elsewhere the keyring is only shown, and used once the deployment supplies it:
 * putting it to use before then would seal values under a key the next restart forgets.
 */
export async function generateAndPlaceKeyring(by: string): Promise<Placement> {
	const document = newKeyringDocument();
	const serialized = serializeKeyring(document);
	const location = writtenToFile(serialized);
	const store = getKeyringStateStore();
	if (location) {
		activate(document, 'file');
		await keyringChecked();
	}
	await store.patch({
		generated: { at: new Date().toISOString(), applied: location !== null, by },
		backupConfirmed: null
	});
	if (location) startPassSoon(0);
	return location
		? { keyring: serialized, applied: true, location }
		: { keyring: serialized, applied: false };
}
