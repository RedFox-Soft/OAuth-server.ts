import type { AdminSession, AdminSessionStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class AdminSessionStore implements AdminSessionStoreInstance {
	private sessions = new Map<string, AdminSession>();

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
		this.sessions.set(session._id, session);
		return session;
	}

	async find(id: string): Promise<AdminSession | null> {
		const s = this.sessions.get(id);
		if (!s) return null;
		const now = Date.now();
		if (s.expiresAt.getTime() <= now || s.absoluteExpiresAt.getTime() <= now) {
			this.sessions.delete(id);
			return null;
		}
		return s;
	}

	async touch(id: string, ttlSeconds: number): Promise<void> {
		const s = this.sessions.get(id);
		if (!s) return;
		const next = new Date(Date.now() + ttlSeconds * 1000);
		s.expiresAt =
			next.getTime() > s.absoluteExpiresAt.getTime()
				? s.absoluteExpiresAt
				: next;
	}

	async destroy(id: string): Promise<void> {
		this.sessions.delete(id);
	}
}
