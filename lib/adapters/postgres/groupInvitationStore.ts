import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import type {
	GroupInvitation,
	GroupInvitationStoreInstance,
	GroupMember
} from '../types.js';
import nanoid from '../../helpers/nanoid.js';

const DATE_FIELDS = ['createdAt', 'expiresAt', 'acceptedAt'] as const;

export class GroupInvitationStore implements GroupInvitationStoreInstance {
	private area: string = STORE_AREAS.groupInvitations;

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

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${invitation._id}, ${invitation}, ${invitation.expiresAt})
		`;

		return invitation;
	}

	async find(id: string): Promise<GroupInvitation | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.invitationOf(rows[0]);
	}

	/*
	 * The expiry bound is applied in the query rather than left to the sweeper. The sweeper runs
	 * periodically, so an expired invitation stays readable for up to a minute after it lapses — and an
	 * invitation that outlives its expiry is a standing offer of access to a group.
	 *
	 * Bounded on the `expires_at` column rather than the document field, so the partial index the
	 * inventory declares can serve it.
	 */
	async findByTokenHash(tokenHash: string): Promise<GroupInvitation | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'tokenHash' = ${tokenHash} AND expires_at > now()
			LIMIT 1
		`;
		return this.invitationOf(rows[0]);
	}

	async listByGroup(groupId: string): Promise<GroupInvitation[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'groupId' = ${groupId}
		`;
		return rows
			.map((row: unknown) => this.invitationOf(row))
			.filter(
				(entry: GroupInvitation | null): entry is GroupInvitation =>
					entry !== null
			);
	}

	async markAccepted(id: string): Promise<void> {
		const handle = sql();
		const acceptedAt = new Date();
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc, '{acceptedAt}', to_jsonb(${acceptedAt}::timestamptz))
			WHERE id = ${id}
		`;
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	async destroyByGroup(groupId: string): Promise<void> {
		const handle = sql();
		await handle`
			DELETE FROM ${handle(this.area)} WHERE doc->>'groupId' = ${groupId}
		`;
	}

	private invitationOf(row: unknown): GroupInvitation | null {
		const doc = docOf<GroupInvitation>(row);
		return doc === undefined ? null : reviveDates(doc, DATE_FIELDS);
	}
}
