import { describe, it, expect } from 'bun:test';
import {
	assertSuperAdmin,
	assertProjectAccess,
	AdminError,
	type AdminContext
} from 'lib/admin/auth/rbac.ts';
import type { Project } from 'lib/adapters/types.ts';

const superAdmin: AdminContext = {
	userId: 'u1',
	email: 'super@x.io',
	superAdmin: true,
	bucketId: 'admin',
	// Super administrators owns nothing, so it is not among the memberships; their reach is instance-wide.
	memberships: [],
	activeGroupId: ''
};
const projectAdmin: AdminContext = {
	userId: 'u2',
	email: 'pa@x.io',
	superAdmin: false,
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

/**
 * @proves Instance-wide operations require a super administrator, and a scoped administrator
 * reaches a project only through the group that owns it.
 */
describe('RBAC guards', () => {
	it('lets a super administrator through an instance-wide check and refuses anyone else with 403', () => {
		expect(() => assertSuperAdmin(superAdmin)).not.toThrow();
		try {
			assertSuperAdmin(projectAdmin);
			throw new Error('should have thrown');
		} catch (e) {
			if (!(e instanceof AdminError)) throw e;
			expect(e.status).toBe(403);
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
			if (!(e instanceof AdminError)) throw e;
			expect(e.status).toBe(403);
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
