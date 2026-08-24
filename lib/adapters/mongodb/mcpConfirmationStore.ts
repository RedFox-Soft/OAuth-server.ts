import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	McpConfirmation,
	McpConfirmationStoreInstance
} from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class McpConfirmationStore implements McpConfirmationStoreInstance {
	private collection = db.collection<McpConfirmation>(
		STORE_AREAS.mcpConfirmation
	);

	async issue(
		data: Omit<McpConfirmation, '_id' | 'createdAt' | 'expiresAt'> & {
			ttlSeconds: number;
		}
	): Promise<McpConfirmation> {
		const { ttlSeconds, ...rest } = data;
		const now = new Date();
		const record: McpConfirmation = {
			_id: nanoid(),
			...rest,
			createdAt: now,
			expiresAt: new Date(now.getTime() + ttlSeconds * 1000)
		};
		await this.collection.insertOne(record);
		return record;
	}

	/*
	 * `findOneAndDelete`, not find-then-delete: single use has to hold under concurrency, and two
	 * agents redeeming the same token simultaneously must not both proceed. The atomic form is what
	 * makes that true rather than likely.
	 *
	 * An expired record is reported as absent, matching the memory adapter. The TTL monitor reaps on
	 * its own schedule — up to a minute behind — so the check cannot be left to the index.
	 */
	async redeem(id: string): Promise<McpConfirmation | null> {
		const record = await this.collection.findOneAndDelete({ _id: id });
		if (!record) return null;
		if (record.expiresAt.getTime() <= Date.now()) return null;
		return record;
	}

	async count(): Promise<number> {
		return this.collection.countDocuments({ expiresAt: { $gt: new Date() } });
	}
}
