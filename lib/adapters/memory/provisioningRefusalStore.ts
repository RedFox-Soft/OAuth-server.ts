import type {
	ProvisioningRefusal,
	ProvisioningRefusalInput,
	ProvisioningRefusalPage,
	ProvisioningRefusalStoreInstance
} from '../types.js';
import { refusalId } from '../refusal_records.js';

/*
 * In-memory refusals. Every write is a synchronous read-and-set with no `await` between, so concurrent
 * notes cannot interleave inside one and no attempt is lost.
 */
export class ProvisioningRefusalStore implements ProvisioningRefusalStoreInstance {
	private refusals = new Map<string, ProvisioningRefusal>();

	async note(input: ProvisioningRefusalInput): Promise<void> {
		const id = refusalId(input.connectionId, input.epoch, input.userId);
		const existing = this.refusals.get(id);
		if (existing) {
			existing.attempts += 1;
			existing.operation = input.operation;
			if (input.at.getTime() > existing.lastAt.getTime()) {
				existing.lastAt = input.at;
			}
			return;
		}
		this.refusals.set(id, {
			_id: id,
			connectionId: input.connectionId,
			bucketId: input.bucketId,
			epoch: input.epoch,
			userId: input.userId,
			operation: input.operation,
			firstAt: input.at,
			lastAt: input.at,
			attempts: 1
		});
	}

	async list(
		connectionId: string,
		epoch: number,
		limit: number
	): Promise<ProvisioningRefusalPage> {
		const matching = [...this.refusals.values()]
			.filter(
				(refusal) =>
					refusal.connectionId === connectionId && refusal.epoch === epoch
			)
			.sort((a, b) => b.lastAt.getTime() - a.lastAt.getTime());
		return {
			refusals: matching
				.slice(0, limit)
				.map((refusal) => structuredClone(refusal)),
			total: matching.length
		};
	}

	async destroyByConnection(connectionId: string): Promise<number> {
		return this.destroyWhere(
			(refusal) => refusal.connectionId === connectionId
		);
	}

	async destroyByBucket(bucketId: string): Promise<number> {
		return this.destroyWhere((refusal) => refusal.bucketId === bucketId);
	}

	private destroyWhere(match: (refusal: ProvisioningRefusal) => boolean) {
		let destroyed = 0;
		for (const [id, refusal] of this.refusals) {
			if (match(refusal)) {
				this.refusals.delete(id);
				destroyed += 1;
			}
		}
		return destroyed;
	}
}
