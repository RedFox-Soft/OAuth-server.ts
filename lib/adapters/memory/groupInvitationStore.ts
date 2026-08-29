import type {
	GroupInvitation,
	GroupInvitationStoreInstance,
	GroupMember
} from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class GroupInvitationStore implements GroupInvitationStoreInstance {
	private invitations = new Map<string, GroupInvitation>();

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
		this.invitations.set(invitation._id, invitation);
		return invitation;
	}

	async find(id: string): Promise<GroupInvitation | null> {
		return this.invitations.get(id) ?? null;
	}

	/*
	 * Expired records are not returned. The MongoDB adapter reaps them on `expiresAt`, but a TTL
	 * monitor is periodic rather than immediate, so both adapters must refuse an expired invitation on
	 * read — otherwise the in-memory suite would never exhibit the window the real one has.
	 */
	async findByTokenHash(tokenHash: string): Promise<GroupInvitation | null> {
		const now = new Date();
		for (const i of this.invitations.values()) {
			if (i.tokenHash === tokenHash && i.expiresAt > now) return i;
		}
		return null;
	}

	async listByGroup(groupId: string): Promise<GroupInvitation[]> {
		return [...this.invitations.values()].filter((i) => i.groupId === groupId);
	}

	async markAccepted(id: string): Promise<void> {
		const i = this.invitations.get(id);
		if (i) i.acceptedAt = new Date();
	}

	async destroy(id: string): Promise<void> {
		this.invitations.delete(id);
	}

	async destroyByGroup(groupId: string): Promise<void> {
		for (const [id, i] of this.invitations) {
			if (i.groupId === groupId) this.invitations.delete(id);
		}
	}
}
