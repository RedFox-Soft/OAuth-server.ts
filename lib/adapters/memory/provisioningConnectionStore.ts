import { entriesOf } from '../../helpers/_/object.js';
import type {
	CredentialSlot,
	DeprovisioningHold,
	HeldConnection,
	NewProvisioningConnection,
	ProvisioningConnection,
	ProvisioningConnectionPatch,
	ProvisioningConnectionStoreInstance
} from '../types.js';
import { UniqueValueTaken } from '../conflicts.js';
import { providerKeyOf } from '../connection_keys.js';

/*
 * In-memory provisioning connections.
 *
 * Both unique keys are enforced by scan, so the "one connection per provider" and "one connection per
 * static token" rules are observable in the default test run. It is not the datastores' guarantee — this
 * cannot survive a concurrent write, which is what database/verify_provisioning_connections.ts is for.
 */
export class ProvisioningConnectionStore implements ProvisioningConnectionStoreInstance {
	private connections = new Map<string, ProvisioningConnection>();

	private takenBy(
		candidate: Pick<ProvisioningConnection, 'providerKey'> &
			Partial<Pick<ProvisioningConnection, 'staticTokenDigest'>>,
		excludeId?: string
	): UniqueValueTaken | null {
		for (const other of this.connections.values()) {
			if (other._id === excludeId) continue;
			if (other.providerKey === candidate.providerKey) {
				return new UniqueValueTaken('provider', candidate.providerKey);
			}
			if (
				candidate.staticTokenDigest !== undefined &&
				other.staticTokenDigest === candidate.staticTokenDigest
			) {
				return new UniqueValueTaken('staticToken', 'digest');
			}
		}
		return null;
	}

	async create(
		data: NewProvisioningConnection
	): Promise<ProvisioningConnection> {
		const now = new Date();
		const connection: ProvisioningConnection = {
			...data,
			providerKey: providerKeyOf(data.bucketId, data.providerId),
			createdAt: now,
			updatedAt: now
		};
		const taken = this.takenBy(connection);
		if (taken) throw taken;
		this.connections.set(connection._id, structuredClone(connection));
		return structuredClone(connection);
	}

	async find(id: string): Promise<ProvisioningConnection | null> {
		const found = this.connections.get(id);
		return found ? structuredClone(found) : null;
	}

	async listByBucket(bucketId: string): Promise<ProvisioningConnection[]> {
		return [...this.connections.values()]
			.filter((c) => c.bucketId === bucketId)
			.map((c) => structuredClone(c));
	}

	async bucketsHolding(): Promise<string[]> {
		const held = new Set<string>();
		for (const connection of this.connections.values()) {
			if (connection.hold) held.add(connection.bucketId);
		}
		return [...held];
	}

	async findByProvider(
		bucketId: string,
		providerId: string
	): Promise<ProvisioningConnection | null> {
		const key = providerKeyOf(bucketId, providerId);
		for (const connection of this.connections.values()) {
			if (connection.providerKey === key) return structuredClone(connection);
		}
		return null;
	}

	async findByStaticTokenDigest(
		digest: string
	): Promise<ProvisioningConnection | null> {
		for (const connection of this.connections.values()) {
			if (connection.staticTokenDigest === digest) {
				return structuredClone(connection);
			}
		}
		return null;
	}

	async findByPreviousStaticTokenDigest(
		digest: string
	): Promise<ProvisioningConnection | null> {
		for (const connection of this.connections.values()) {
			if (connection.previousStaticToken?.digest === digest) {
				return structuredClone(connection);
			}
		}
		return null;
	}

	async listHeld(): Promise<HeldConnection[]> {
		return [...this.connections.values()].flatMap((connection) =>
			connection.hold
				? [
						{
							_id: connection._id,
							bucketId: connection.bucketId,
							displayName: connection.displayName,
							hold: structuredClone(connection.hold),
							...(connection.tallyEpoch !== undefined
								? { tallyEpoch: connection.tallyEpoch }
								: {})
						}
					]
				: []
		);
	}

	/* Nothing awaits between the read and the write, so racing callers are serialised as the databases do. */
	async noteCredentialUse(
		id: string,
		slot: CredentialSlot,
		which: 'current' | 'previous',
		at: Date
	): Promise<void> {
		const current = this.connections.get(id);
		if (!current) return;
		if (which === 'previous') {
			const previous =
				slot === 'secret'
					? current.previousSecret
					: current.previousStaticToken;
			if (previous) previous.lastUsedAt = at;
			return;
		}
		if (slot === 'secret') {
			const credential = current.oauthCredential;
			if (credential?.kind === 'secret' && !credential.firstUsedAt) {
				credential.firstUsedAt = at;
			}
		} else if (current.staticTokenDigest && !current.staticTokenFirstUsedAt) {
			current.staticTokenFirstUsedAt = at;
		}
	}

	async retirePrevious(
		id: string,
		slot: CredentialSlot,
		digest: string
	): Promise<boolean> {
		const current = this.connections.get(id);
		const field = slot === 'secret' ? 'previousSecret' : 'previousStaticToken';
		if (current?.[field]?.digest !== digest) return false;
		Reflect.deleteProperty(current, field);
		current.updatedAt = new Date();
		return true;
	}

	async update(
		id: string,
		patch: ProvisioningConnectionPatch
	): Promise<ProvisioningConnection | null> {
		const current = this.connections.get(id);
		if (!current) return null;
		const next: ProvisioningConnection = {
			...current,
			...patch,
			updatedAt: new Date()
		};
		/* A key present with an undefined value removes the field, as the user store's patch does. */
		for (const [field, value] of entriesOf(patch)) {
			if (value === undefined) Reflect.deleteProperty(next, field);
		}
		const taken = this.takenBy(next, id);
		if (taken) throw taken;
		/* Cloned in: the use writes below mutate nested values, which must not reach the caller's patch. */
		this.connections.set(id, structuredClone(next));
		return structuredClone(next);
	}

	async touch(id: string, at: Date): Promise<void> {
		const current = this.connections.get(id);
		if (current) current.lastUsedAt = at;
	}

	/* Nothing awaits between the read and the write, so racing callers are serialised as the databases do. */
	async holdIfFree(id: string, hold: DeprovisioningHold): Promise<boolean> {
		const current = this.connections.get(id);
		if (!current || current.hold) return false;
		current.hold = structuredClone(hold);
		current.updatedAt = new Date();
		return true;
	}

	async releaseHold(id: string): Promise<ProvisioningConnection | null> {
		const current = this.connections.get(id);
		if (!current?.hold) return null;
		Reflect.deleteProperty(current, 'hold');
		current.tallyEpoch = (current.tallyEpoch ?? 0) + 1;
		current.updatedAt = new Date();
		return structuredClone(current);
	}

	async destroy(id: string): Promise<void> {
		this.connections.delete(id);
	}

	async destroyByBucket(bucketId: string): Promise<string[]> {
		const removed: string[] = [];
		for (const [id, connection] of this.connections) {
			if (connection.bucketId === bucketId) {
				this.connections.delete(id);
				removed.push(id);
			}
		}
		return removed;
	}
}
