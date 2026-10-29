import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { KeyringDocument } from 'lib/sealing/keyring.ts';

function keyOf(fill: number): string {
	return Buffer.alloc(32, fill).toString('base64url');
}

/* The keyring every spec file runs under (test_helper.ts bootstrap), so the whole suite reads and writes sealed storage. */
export const TEST_KEYRING: KeyringDocument = {
	v: 1,
	write: '20261029-test',
	keys: { '20261029-test': keyOf(7) }
};

/* A keyring that shares no key with the test keyring: everything sealed under the test keyring is unreadable with it. */
export const OTHER_KEYRING: KeyringDocument = {
	v: 1,
	write: '20261030-othr',
	keys: { '20261030-othr': keyOf(9) }
};

/* The test keyring's key id with different key material: what a mistyped keyring looks like. */
export const SAME_KID_WRONG_KEYRING: KeyringDocument = {
	v: 1,
	write: '20261029-test',
	keys: { '20261029-test': keyOf(8) }
};

/* The test keyring with a second key staged: readable, not yet written with. */
export const STAGED_KEYRING: KeyringDocument = {
	v: 1,
	write: '20261029-test',
	keys: { '20261029-test': keyOf(7), '20261031-next': keyOf(11) }
};

/* The staged key made the write key, the old one still readable. */
export const ROTATED_KEYRING: KeyringDocument = {
	v: 1,
	write: '20261031-next',
	keys: { '20261029-test': keyOf(7), '20261031-next': keyOf(11) }
};

/* The raw key bytes of every fixture, in both spellings a leak could take, for the secrecy sweeps. */
export const FIXTURE_KEY_MATERIAL: string[] = [7, 8, 9, 11].flatMap((fill) => [
	keyOf(fill),
	Buffer.alloc(32, fill).toString('base64'),
	Buffer.alloc(32, fill).toString('hex')
]);

/* A directory under the system temporary directory, removed by the returned function. */
export function withTempKeyringDir(): { dir: string; remove: () => void } {
	const dir = mkdtempSync(join(tmpdir(), 'foxauth-keyring-'));
	return { dir, remove: () => rmSync(dir, { recursive: true, force: true }) };
}
