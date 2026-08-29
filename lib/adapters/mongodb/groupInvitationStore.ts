import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import type {
	GroupInvitation,
	GroupInvitationStoreInstance,
	GroupMember
} from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class GroupInvitationStore implements GroupInvitationStoreInstance {
	private collection = db.collection<GroupInvitation>(
		STORE_AREAS.groupInvitations
	);

	async create(data: {
		_id?: string;
		groupId: string;
		email: string;
		role: GroupMember['role'];
		invitedBy: string;
		tokenHash: string;
		ttlSeconds: number;
	}): Promise<GroupInvitation> {
		const now = new Date();
		const invitation: GroupInvitation = {
			_id: data._id ?? nanoid(),
			groupId: data.groupId,
			email: data.email,
			role: data.role,
			invitedBy: data.invitedBy,
			tokenHash: data.tokenHash,
			expiresAt: new Date(now.getTime() + data.ttlSeconds * 1000),
			acceptedAt: null,
			createdAt: now
		};
		await this.collection.insertOne(invitation);
		return invitation;
	}

	async find(id: string): Promise<GroupInvitation | null> {
		return this.collection.findOne({ _id: id });
	}

	/*
	 * The `expiresAt` bound is applied in the query rather than left to the TTL index. A TTL monitor
	 * runs periodically, so an expired invitation remains readable for up to a minute after it lapses —
	 * and an invitation that outlives its expiry is a standing offer of access to a group.
	 */
	async findByTokenHash(tokenHash: string): Promise<GroupInvitation | null> {
		return this.collection.findOne({
			tokenHash,
			expiresAt: { $gt: new Date() }
		});
	}

	async listByGroup(groupId: string): Promise<GroupInvitation[]> {
		return this.collection.find({ groupId }).toArray();
	}

	async markAccepted(id: string): Promise<void> {
		await this.collection.updateOne(
			{ _id: id },
			{ $set: { acceptedAt: new Date() } }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}

	async destroyByGroup(groupId: string): Promise<void> {
		await this.collection.deleteMany({ groupId });
	}
}
