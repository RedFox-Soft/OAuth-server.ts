import crypto from 'crypto';

import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { PlanCatalogue } from '../../consts/plans.js';
import { documentOf } from '../documents.js';
import type { PlanCatalogueStoreInstance } from '../types.js';

function derivedId(name: string): string {
	return crypto
		.createHash('sha256')
		.update(name)
		.digest('hex')
		.substring(0, 24);
}

/*
 * The plan catalogue (specs/102). Same area as the config store, the SMTP settings and the singleton secrets — see
 * the note on STORE_AREAS.serviceConfig — told apart only by the derived id below.
 */
export class PlanCatalogueStore implements PlanCatalogueStoreInstance {
	private area: string = STORE_AREAS.serviceConfig;
	private catalogueId = derivedId('planCatalogue');

	async get(): Promise<PlanCatalogue | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${this.catalogueId}
		`;
		const doc = docOf(rows[0]);
		return doc === undefined ? null : documentOf(this.area, PlanCatalogue, doc);
	}

	async set(catalogue: PlanCatalogue): Promise<void> {
		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${this.catalogueId}, ${catalogue}, NULL)
			ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc
		`;
	}
}
