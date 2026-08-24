import type {
	McpConfirmation,
	McpConfirmationStoreInstance
} from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class McpConfirmationStore implements McpConfirmationStoreInstance {
	private records = new Map<string, McpConfirmation>();

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
		this.records.set(record._id, record);
		return record;
	}

	/*
	 * Read and delete together, so two concurrent redemptions of one token cannot both succeed. The
	 * MongoDB implementation gets the same property from findOneAndDelete; here the single-threaded
	 * event loop gives it, but the delete still precedes the return rather than following it, so the
	 * two implementations are the same shape.
	 *
	 * An expired record is deleted and reported as absent: the caller must not be able to tell an
	 * expired token from an unknown one, because neither is redeemable and the difference would only
	 * help someone probing.
	 */
	async redeem(id: string): Promise<McpConfirmation | null> {
		const record = this.records.get(id);
		if (!record) return null;
		this.records.delete(id);
		if (record.expiresAt.getTime() <= Date.now()) return null;
		return record;
	}

	async count(): Promise<number> {
		// Expired-but-unreaped records are not live. The memory adapter has no TTL monitor, so the
		// filter is what makes its count agree with MongoDB's after an expiry.
		const now = Date.now();
		let live = 0;
		for (const record of this.records.values()) {
			if (record.expiresAt.getTime() > now) live += 1;
		}
		return live;
	}
}
