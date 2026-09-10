import crypto from 'crypto';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { AdapterConfigStore } from '../types.js';

/*
 * The persisted ApplicationConfig — one row in the shared serviceConfig area, told apart from the
 * SMTP settings and the three singleton secrets by a derived id, exactly as on the other backend.
 *
 * The config is the whole document here rather than a `config` field inside one. MongoDB nests it
 * because a BSON document has no other place to put its bookkeeping; a jsonb column is already just
 * the value, so nesting would be a wrapper that exists only to be unwrapped.
 */
function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
		.digest('hex')
		.substring(0, 24);
}

class ConfigStore implements AdapterConfigStore {
	static instance = new ConfigStore();
	private area: string = STORE_AREAS.serviceConfig;
	private configId = derivedId('appConfig');

	async get(): Promise<Record<string, unknown> | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${this.configId}
		`;
		return docOf<Record<string, unknown>>(rows[0]) ?? null;
	}

	async set(config: Record<string, unknown>): Promise<void> {
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${this.configId}, ${config}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
		`;
	}
}

export const configStore = ConfigStore.instance;
