import crypto from 'crypto';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { entriesOf, isRecord } from '../../helpers/_/object.js';
import {
	KeyringState,
	type KeyringStatePatch,
	type KeyringStateStoreInstance
} from '../types.js';

function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
		.digest('hex')
		.substring(0, 24);
}

/* Held to the shape the keyring gives a kid before it reaches a statement, as on the other backend. */
const KID = /^\d{8}-[A-Za-z0-9_-]{4}$/;

function checkedKid(kid: string): string {
	if (!KID.test(kid)) {
		throw new Error(`'${kid}' is not a keyring key id`);
	}
	return kid;
}

export class KeyringStateStore implements KeyringStateStoreInstance {
	private area: string = STORE_AREAS.serviceConfig;
	private stateId = derivedId('keyringState');

	async read(): Promise<KeyringState | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${this.stateId}
		`;
		const stored = docOf(rows[0]);
		if (stored === undefined) return null;
		if (!isRecord(stored)) return documentOf(this.area, KeyringState, stored);
		const { updatedAt, ...doc } = stored;
		return documentOf(this.area, KeyringState, doc);
	}

	/*
	 * Insert-if-absent in one statement: the row is created holding this fingerprint, or the existing row
	 * gains it only while it records none for the kid. A process that loses either race writes nothing and
	 * reads the winner's value.
	 */
	async addFingerprintIfAbsent(
		kid: string,
		fingerprint: string
	): Promise<string> {
		const id = checkedKid(kid);
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} AS k (id, doc, expires_at)
			VALUES (${this.stateId}, ${{ fingerprints: { [id]: fingerprint } }}, NULL)
			ON CONFLICT (id) DO UPDATE
			SET doc = k.doc || jsonb_build_object(
				'fingerprints',
				COALESCE(k.doc->'fingerprints', '{}'::jsonb)
					|| jsonb_build_object(${id}::text, ${fingerprint}::text)
			)
			WHERE (k.doc->'fingerprints'->${id}::text) IS NULL
		`;
		const stored = (await this.read())?.fingerprints ?? {};
		const recorded = Object.hasOwn(stored, id) ? stored[id] : undefined;
		if (recorded === undefined) {
			throw new Error(`the fingerprint of key ${id} could not be read back`);
		}
		return recorded;
	}

	async patch(fields: KeyringStatePatch): Promise<void> {
		const set: Record<string, unknown> = {};
		const removed: string[] = [];
		for (const [name, value] of entriesOf(fields)) {
			if (value === null) removed.push(name);
			else if (value !== undefined) set[name] = value;
		}
		const handle = sql();
		// One `- key` per removed field, each key a bound parameter, rather than an array parameter.
		let kept = handle`k.doc`;
		for (const name of removed) kept = handle`${kept} - ${name}::text`;
		await handle`
			INSERT INTO ${handle(this.area)} AS k (id, doc, expires_at)
			VALUES (${this.stateId}, ${{ fingerprints: {}, ...set }}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = (${kept}) || ${set}
		`;
	}
}
