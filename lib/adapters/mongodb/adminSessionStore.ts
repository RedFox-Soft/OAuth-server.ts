import { db } from './db.js';
import type { AdminSession, AdminSessionStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class AdminSessionStore implements AdminSessionStoreInstance {
	private collection = db.collection<AdminSession>('adminSession');

	async create(data: {
		userId: string;
		bucketId: string;
		tokens: AdminSession['tokens'];
		ttlSeconds: number;
		absoluteTtlSeconds: number;
	}): Promise<AdminSession> {
		const now = new Date();
		const session: AdminSession = {
			_id: nanoid(),
			userId: data.userId,
			bucketId: data.bucketId,
			tokens: data.tokens,
			createdAt: now,
			expiresAt: new Date(now.getTime() + data.ttlSeconds * 1000),
			absoluteExpiresAt: new Date(
				now.getTime() + data.absoluteTtlSeconds * 1000
			)
		};
		await this.collection.insertOne(session);
		return session;
	}

	async find(id: string): Promise<AdminSession | null> {
		const s = await this.collection.findOne({ _id: id });
		if (!s) return null;
		const now = Date.now();
		if (s.expiresAt.getTime() <= now || s.absoluteExpiresAt.getTime() <= now) {
			await this.collection.deleteOne({ _id: id });
			return null;
		}
		return s;
	}

	async touch(id: string, ttlSeconds: number): Promise<void> {
		const s = await this.collection.findOne({ _id: id });
		if (!s) return;
		const next = new Date(Date.now() + ttlSeconds * 1000);
		const expiresAt =
			next.getTime() > s.absoluteExpiresAt.getTime()
				? s.absoluteExpiresAt
				: next;
		await this.collection.updateOne({ _id: id }, { $set: { expiresAt } });
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
