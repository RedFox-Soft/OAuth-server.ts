import crypto from 'crypto';
import { ObjectId } from 'mongodb';
import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { SmtpSettings, type SmtpSettingsStoreInstance } from '../types.js';

function stringTo24CharHex(str: string) {
	const hash = crypto.createHash('sha256').update(str).digest('hex');
	return hash.substring(0, 24);
}

export class SmtpSettingsStore implements SmtpSettingsStoreInstance {
	/* Same area as configStore — see the note on STORE_AREAS.serviceConfig. The two are told apart
	 * only by the derived ObjectId below, which is why the inventory carries one entry, not two. */
	private collectionName: string = STORE_AREAS.serviceConfig;
	private settingsId = new ObjectId(stringTo24CharHex('smtpSettings'));

	async get(): Promise<SmtpSettings | null> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ _id: this.settingsId });
		const settings: unknown = result?.settings ?? null;
		return settings === null
			? null
			: documentOf(this.collectionName, SmtpSettings, settings);
	}

	async set(settings: SmtpSettings): Promise<void> {
		await db
			.collection(this.collectionName)
			.updateOne(
				{ _id: this.settingsId },
				{ $set: { settings, updatedAt: new Date() } },
				{ upsert: true }
			);
	}
}
