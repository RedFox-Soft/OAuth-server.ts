import crypto from 'crypto';
import { ObjectId } from 'mongodb';

import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { entriesOf } from '../../helpers/_/object.js';
import {
	KeyringState,
	type KeyringStatePatch,
	type KeyringStateStoreInstance
} from '../types.js';

function stringTo24CharHex(value: string): string {
	return crypto
		.createHash('sha256')
		.update(value)
		.digest('hex')
		.substring(0, 24);
}

/* A duplicate key on the fixed _id is how an upsert that found the fingerprint already recorded learns it. */
function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

/*
 * A kid becomes part of a field path (`fingerprints.<kid>`), so it is held to the shape the keyring gives
 * it before it reaches one: a dot or a leading `$` would address a different field, or an operator.
 */
const KID = /^\d{8}-[A-Za-z0-9_-]{4}$/;

function checkedKid(kid: string): string {
	if (!KID.test(kid)) {
		throw new Error(`'${kid}' is not a keyring key id`);
	}
	return kid;
}

export class KeyringStateStore implements KeyringStateStoreInstance {
	private collectionName: string = STORE_AREAS.serviceConfig;
	private stateId = new ObjectId(stringTo24CharHex('keyringState'));

	private collection() {
		// Untyped documents: the paths written here (`fingerprints.<kid>`) are built at run time.
		return db.collection(this.collectionName);
	}

	async read(): Promise<KeyringState | null> {
		const found = await this.collection().findOne({ _id: this.stateId });
		if (!found) return null;
		const { _id, updatedAt, ...doc } = found;
		return documentOf(this.collectionName, KeyringState, doc);
	}

	/*
	 * One conditional upsert: it sets the fingerprint only where none is recorded for the kid, and creates the
	 * document when there is none. Where the document exists and already records the kid the filter misses,
	 * the upsert's insert collides on the fixed _id, and that collision is the "already recorded" answer.
	 */
	async addFingerprintIfAbsent(
		kid: string,
		fingerprint: string
	): Promise<string> {
		const path = `fingerprints.${checkedKid(kid)}`;
		try {
			await this.collection().updateOne(
				{ _id: this.stateId, [path]: { $exists: false } },
				{ $set: { [path]: fingerprint } },
				{ upsert: true }
			);
		} catch (error) {
			if (!isDuplicateKey(error)) throw error;
		}
		const stored = (await this.read())?.fingerprints ?? {};
		const recorded = Object.hasOwn(stored, kid) ? stored[kid] : undefined;
		if (recorded === undefined) {
			throw new Error(`the fingerprint of key ${kid} could not be read back`);
		}
		return recorded;
	}

	async patch(fields: KeyringStatePatch): Promise<void> {
		const set: Record<string, unknown> = {};
		const unset: Record<string, ''> = {};
		for (const [name, value] of entriesOf(fields)) {
			if (value === null) unset[name] = '';
			else if (value !== undefined) set[name] = value;
		}
		await this.collection().updateOne(
			{ _id: this.stateId },
			{
				$setOnInsert: { fingerprints: {} },
				// An empty $set or $unset is rejected by MongoDB, so each appears only when it has work.
				...(Object.keys(set).length ? { $set: set } : {}),
				...(Object.keys(unset).length ? { $unset: unset } : {})
			},
			{ upsert: true }
		);
	}
}
