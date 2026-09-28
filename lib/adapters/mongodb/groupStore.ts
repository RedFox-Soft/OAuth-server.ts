import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import { Group, type GroupMember, type GroupStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

function groupOf(found: unknown): Group | null {
	return found ? documentOf(STORE_AREAS.groups, Group, found) : null;
}

function groupsOf(found: unknown[]): Group[] {
	return found.map((group) => documentOf(STORE_AREAS.groups, Group, group));
}

export class GroupStore implements GroupStoreInstance {
	private collection = db.collection<Group>(STORE_AREAS.groups);

	async create(data: {
		_id?: string;
		name: string;
		kind?: Group['kind'];
		members?: GroupMember[];
	}): Promise<Group> {
		const now = new Date();
		const group: Group = {
			_id: data._id ?? nanoid(),
			name: data.name,
			kind: data.kind ?? 'regular',
			members: data.members ?? [],
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(group);
		return group;
	}

	async find(id: string): Promise<Group | null> {
		return groupOf(await this.collection.findOne({ _id: id }));
	}

	async list(): Promise<Group[]> {
		return groupsOf(await this.collection.find().toArray());
	}

	/*
	 * On the request path for every admin call — `contextFor` resolves the caller's memberships here —
	 * hence the multikey `members.userId` index declared in the storage inventory.
	 */
	async listByMember(userId: string): Promise<Group[]> {
		return groupsOf(
			await this.collection.find({ 'members.userId': userId }).toArray()
		);
	}

	async findPersonalFor(userId: string): Promise<Group | null> {
		return groupOf(
			await this.collection.findOne({
				kind: 'personal',
				'members.userId': userId
			})
		);
	}

	async update(
		id: string,
		patch: Partial<Pick<Group, 'name' | 'members'>>
	): Promise<Group | null> {
		return groupOf(
			await this.collection.findOneAndUpdate(
				{ _id: id },
				{ $set: { ...patch, updatedAt: new Date() } },
				{ returnDocument: 'after' }
			)
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
