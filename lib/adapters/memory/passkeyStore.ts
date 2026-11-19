import type { Passkey, PasskeyStoreInstance } from '../types.js';

/*
 * In-memory passkeys (specs/139). The unique `(bucketId, credentialId)` and the conditional writes the datastores
 * give are checked here synchronously, so the rules they enforce are observable in the default test run.
 */
export class PasskeyStore implements PasskeyStoreInstance {
	private records = new Map<string, Passkey>();

	async create(record: Passkey): Promise<'created' | 'exists'> {
		const taken = this.matching(
			(held) =>
				held.bucketId === record.bucketId &&
				held.credentialId === record.credentialId
		);
		if (taken.length > 0 || this.records.has(record._id)) return 'exists';
		this.records.set(record._id, structuredClone(record));
		return 'created';
	}

	async findByCredential(
		bucketId: string,
		credentialId: string
	): Promise<Passkey | null> {
		const found = [...this.records.values()].find(
			(held) => held.bucketId === bucketId && held.credentialId === credentialId
		);
		return found ? structuredClone(found) : null;
	}

	async find(bucketId: string, id: string): Promise<Passkey | null> {
		const found = this.owned(bucketId, id);
		return found ? structuredClone(found) : null;
	}

	async listOf(bucketId: string, accountId: string): Promise<Passkey[]> {
		return this.matching(
			(held) => held.bucketId === bucketId && held.accountId === accountId
		).map((held) => structuredClone(held));
	}

	async countOf(bucketId: string, accountId: string): Promise<number> {
		return this.matching(
			(held) => held.bucketId === bucketId && held.accountId === accountId
		).length;
	}

	async recordUse(
		bucketId: string,
		id: string,
		use: { counter: number; backedUp: boolean; at: Date }
	): Promise<boolean> {
		const held = this.owned(bucketId, id);
		if (!held || held.copiedAt !== undefined) return false;
		const moves =
			use.counter === 0 ? held.counter === 0 : held.counter < use.counter;
		if (!moves) return false;
		held.counter = use.counter;
		held.backedUp = use.backedUp;
		held.lastUsedAt = new Date(use.at);
		return true;
	}

	async markCopied(bucketId: string, id: string, at: Date): Promise<void> {
		const held = this.owned(bucketId, id);
		if (held && held.copiedAt === undefined) held.copiedAt = new Date(at);
	}

	async rename(
		bucketId: string,
		accountId: string,
		id: string,
		name: string | undefined
	): Promise<boolean> {
		const held = this.owned(bucketId, id);
		if (!held || held.accountId !== accountId) return false;
		if (name === undefined) delete held.name;
		else held.name = name;
		return true;
	}

	async remove(
		bucketId: string,
		accountId: string,
		id: string
	): Promise<boolean> {
		const held = this.owned(bucketId, id);
		if (!held || held.accountId !== accountId) return false;
		return this.records.delete(id);
	}

	async removeAddedSince(
		bucketId: string,
		accountId: string,
		since: Date
	): Promise<number> {
		return this.removeWhere(
			(held) =>
				held.bucketId === bucketId &&
				held.accountId === accountId &&
				held.createdAt.getTime() >= since.getTime()
		);
	}

	async removeAllOf(bucketId: string, accountId: string): Promise<number> {
		return this.removeWhere(
			(held) => held.bucketId === bucketId && held.accountId === accountId
		);
	}

	async removeAllIn(bucketId: string): Promise<number> {
		return this.removeWhere((held) => held.bucketId === bucketId);
	}

	async spendNotMe(
		bucketId: string,
		id: string,
		digest: string,
		now: number
	): Promise<boolean> {
		const held = this.owned(bucketId, id);
		if (!held?.notMe || held.notMe.digest !== digest || held.notMe.exp <= now)
			return false;
		delete held.notMe;
		return true;
	}

	async holdersIn(bucketId: string): Promise<string[]> {
		return [
			...new Set(
				this.matching((held) => held.bucketId === bucketId).map(
					(held) => held.accountId
				)
			)
		];
	}

	private owned(bucketId: string, id: string): Passkey | undefined {
		const held = this.records.get(id);
		return held && held.bucketId === bucketId ? held : undefined;
	}

	private matching(predicate: (held: Passkey) => boolean): Passkey[] {
		return [...this.records.values()].filter(predicate);
	}

	private removeWhere(predicate: (held: Passkey) => boolean): number {
		const gone = this.matching(predicate);
		for (const held of gone) this.records.delete(held._id);
		return gone.length;
	}
}
