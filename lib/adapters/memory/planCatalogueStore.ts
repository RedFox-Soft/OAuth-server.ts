import type { PlanCatalogue } from '../../consts/plans.js';
import type { PlanCatalogueStoreInstance } from '../types.js';

export class PlanCatalogueStore implements PlanCatalogueStoreInstance {
	private catalogue: PlanCatalogue | null = null;

	async get(): Promise<PlanCatalogue | null> {
		return this.catalogue === null ? null : structuredClone(this.catalogue);
	}

	async set(catalogue: PlanCatalogue): Promise<void> {
		this.catalogue = structuredClone(catalogue);
	}
}
