import crypto from 'crypto';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type { SmtpSettings, SmtpSettingsStoreInstance } from '../types.js';

function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
		.digest('hex')
		.substring(0, 24);
}

/*
 * The runtime SMTP transport settings.
 *
 * Same area as the config store and the three singleton secrets — see the note on
 * STORE_AREAS.serviceConfig — told apart only by the derived id below, which is why the inventory
 * carries one entry for all of them rather than five.
 *
 * Nothing here masks the password: this is the storage layer, and it stores what it is given. The
 * write-only handling that keeps the password out of a response lives in the admin route, which is
 * where the distinction between "what is stored" and "what a caller may read back" belongs.
 */
export class SmtpSettingsStore implements SmtpSettingsStoreInstance {
	private area: string = STORE_AREAS.serviceConfig;
	private settingsId = derivedId('smtpSettings');

	async get(): Promise<SmtpSettings | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${this.settingsId}
		`;
		const doc = docOf<SmtpSettings>(rows[0]);
		return doc ?? null;
	}

	async set(settings: SmtpSettings): Promise<void> {
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${this.settingsId}, ${settings}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
		`;
	}
}
