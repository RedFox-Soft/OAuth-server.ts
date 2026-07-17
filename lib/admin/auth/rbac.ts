import { Elysia } from 'elysia';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from '../../adapters/index.js';
import type { Project, UserBucket } from '../../adapters/types.js';
import { ADMIN_SESSION_COOKIE, ADMIN_SESSION_TTL_SECONDS } from '../consts.js';

export interface AdminContext {
	userId: string;
	roles: string[];
	bucketId: string;
	managedProjectIds: string[];
}

export class AdminError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

export function assertAuth(admin: AdminContext | null): AdminContext {
	if (!admin) throw new AdminError(401, 'authentication required');
	return admin;
}

export function assertRole(admin: AdminContext, role: string): void {
	if (!admin.roles.includes(role)) {
		throw new AdminError(403, `role ${role} required`);
	}
}

export function assertProjectAccess(
	admin: AdminContext,
	project: Project
): void {
	if (admin.roles.includes('super_admin')) return;
	if (project.type === 'admin' || !project.managedBy.includes(admin.userId)) {
		throw new AdminError(403, 'no access to this project');
	}
}

export function assertBucketAccess(
	admin: AdminContext,
	bucket: UserBucket
): void {
	if (admin.roles.includes('super_admin')) return;
	if (!bucket.managedBy.includes(admin.userId)) {
		throw new AdminError(403, 'no access to this bucket');
	}
}

export const resolveAdmin = new Elysia({ name: 'admin-resolve' }).derive(
	{ as: 'scoped' },
	async ({ cookie }): Promise<{ admin: AdminContext | null }> => {
		const sessionId = cookie[ADMIN_SESSION_COOKIE]?.value as string | undefined;
		if (!sessionId) return { admin: null };
		const session = await adminSessionStore.find(sessionId);
		if (!session) return { admin: null };
		const user = await getUserStore(session.bucketId).find(session.userId);
		if (!user || !user.active) return { admin: null };
		await adminSessionStore.touch(sessionId, ADMIN_SESSION_TTL_SECONDS);
		const managed = await getProjectStore().listByManager(user._id);
		return {
			admin: {
				userId: user._id,
				roles: user.roles,
				bucketId: session.bucketId,
				managedProjectIds: managed.map((p) => p._id)
			}
		};
	}
);
