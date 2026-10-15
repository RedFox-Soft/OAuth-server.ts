import crypto from 'crypto';
import { ObjectId } from 'mongodb';
import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { PlanCatalogue } from '../../consts/plans.js';
import { documentOf } from '../documents.js';
import type { PlanCatalogueStoreInstance } from '../types.js';

function stringTo24CharHex(str: string) {
	const hash = crypto.createHash('sha256').update(str).digest('hex');
	return hash.substring(0, 24);
}

export class PlanCatalogueStore implements PlanCatalogueStoreInstance {
	/* Same area as configStore and the SMTP settings — see the note on STORE_AREAS.serviceConfig — told apart only
	 * by the derived ObjectId below. */
	private collectionName: string = STORE_AREAS.serviceConfig;
	private catalogueId = new ObjectId(stringTo24CharHex('planCatalogue'));

	async get(): Promise<PlanCatalogue | null> {
		const result = await db
			.collection(this.collectionName)
			.findOne({ _id: this.catalogueId });
		const catalogue: unknown = result?.catalogue ?? null;
		return catalogue === null
			? null
			: documentOf(this.collectionName, PlanCatalogue, catalogue);
	}

	async set(catalogue: PlanCatalogue): Promise<void> {
		await db
			.collection(this.collectionName)
			.updateOne(
				{ _id: this.catalogueId },
				{ $set: { catalogue, updatedAt: new Date() } },
				{ upsert: true }
			);
	}
}
