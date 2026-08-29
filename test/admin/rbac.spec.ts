import { describe, it, expect } from 'bun:test';
import {
	assertRole,
	assertProjectAccess,
	AdminError,
	type AdminContext
} from 'lib/admin/auth/rbac.ts';
import type { Project } from 'lib/adapters/types.ts';

const superAdmin: AdminContext = {
	userId: 'u1',
	email: 'super@x.io',
	roles: ['super_admin'],
	bucketId: 'admin',
	// A super administrator belongs to no group by virtue of the role; their reach is instance-wide.
	memberships: [],
	activeGroupId: ''
};
const projectAdmin: AdminContext = {
	userId: 'u2',
	email: 'pa@x.io',
	roles: ['project_admin'],
	bucketId: 'admin',
	memberships: [{ groupId: 'g1', role: 'owner' as const }],
	activeGroupId: 'g1'
};
const project = (over: Partial<Project>): Project => ({
	_id: 'p1',
	name: 'Acme',
	slug: 'acme',
	type: 'regular',
	ownerGroupId: 'g1',
	bucketId: null,
	clientIds: [],
	corsOrigins: [],
	createdAt: new Date(),
	updatedAt: new Date(),
	...over
});

describe('RBAC guards', () => {
	it('assertRole passes for super_admin, throws 403 otherwise', () => {
		expect(() => assertRole(superAdmin, 'super_admin')).not.toThrow();
		try {
			assertRole(projectAdmin, 'super_admin');
			throw new Error('should have thrown');
		} catch (e) {
			expect((e as AdminError).status).toBe(403);
		}
	});

	it('project admin can access a project their group owns', () => {
		expect(() => assertProjectAccess(projectAdmin, project({}))).not.toThrow();
	});

	it('project admin cannot access the admin project even by id', () => {
		try {
			assertProjectAccess(
				projectAdmin,
				project({ type: 'admin', ownerGroupId: 'g1' })
			);
			throw new Error('should have thrown');
		} catch (e) {
			expect((e as AdminError).status).toBe(403);
		}
	});

	it('super admin can access any project', () => {
		expect(() =>
			assertProjectAccess(
				superAdmin,
				project({ type: 'admin', ownerGroupId: 'g9' })
			)
		).not.toThrow();
	});
});
