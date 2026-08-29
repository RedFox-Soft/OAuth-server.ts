import type { Group, GroupMember, GroupStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class GroupStore implements GroupStoreInstance {
	private groups = new Map<string, Group>();

	async create(data: {
		_id?: string;
		name: string;
		kind?: Group['kind'];
		members?: GroupMember[];
		needsReview?: boolean;
	}): Promise<Group> {
		const now = new Date();
		const group: Group = {
			_id: data._id ?? nanoid(),
			name: data.name,
			kind: data.kind ?? 'regular',
			members: data.members ?? [],
			needsReview: data.needsReview ?? false,
			createdAt: now,
			updatedAt: now
		};
		this.groups.set(group._id, group);
		return group;
	}

	async find(id: string): Promise<Group | null> {
		return this.groups.get(id) ?? null;
	}

	async list(): Promise<Group[]> {
		return [...this.groups.values()];
	}

	async listByMember(userId: string): Promise<Group[]> {
		return [...this.groups.values()].filter((g) =>
			g.members.some((m) => m.userId === userId)
		);
	}

	async findPersonalFor(userId: string): Promise<Group | null> {
		for (const g of this.groups.values()) {
			if (g.kind === 'personal' && g.members.some((m) => m.userId === userId)) {
				return g;
			}
		}
		return null;
	}

	async update(
		id: string,
		patch: Partial<Pick<Group, 'name' | 'members' | 'needsReview'>>
	): Promise<Group | null> {
		const g = this.groups.get(id);
		if (!g) return null;
		Object.assign(g, patch, { updatedAt: new Date() });
		return g;
	}

	async destroy(id: string): Promise<void> {
		this.groups.delete(id);
	}
}
