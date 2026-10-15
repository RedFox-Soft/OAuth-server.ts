import { describe, it, expect } from 'bun:test';
import {
	assertSuperAdmin,
	assertBucketAccess,
	AdminError,
	type AdminContext
} from 'lib/admin/auth/rbac.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

const superAdmin: AdminContext = {
	userId: 'u1',
	email: 'super@x.io',
	superAdmin: true,
	bucketId: 'admin',
	// Super administrators owns nothing, so it is not among the memberships; their reach is instance-wide.
	memberships: [],
	activeGroupId: '',
	signedInWith: null
};
const groupAdmin: AdminContext = {
	userId: 'u2',
	email: 'pa@x.io',
	superAdmin: false,
	bucketId: 'admin',
	memberships: [{ groupId: 'g1', role: 'owner' as const }],
	activeGroupId: 'g1',
	signedInWith: null
};
const bucket = (over: Partial<UserBucket>): UserBucket => ({
	_id: 'b1',
	name: 'Acme users',
	ownerGroupId: 'g1',
	passwordLogin: true,
	federation: [],
	registrationOpen: false,
	emailVerificationRequired: false,
	verificationMethod: 'link',
	totpRequired: false,
	createdAt: new Date(),
	updatedAt: new Date(),
	...over
});

/**
 * @proves Instance-wide operations require a super administrator, and a scoped administrator
 * reaches a bucket only through the group that owns it.
 */
describe('RBAC guards', () => {
	it('lets a super administrator through an instance-wide check and refuses anyone else with 403', () => {
		expect(() => assertSuperAdmin(superAdmin)).not.toThrow();
		try {
			assertSuperAdmin(groupAdmin);
			throw new Error('should have thrown');
		} catch (e) {
			if (!(e instanceof AdminError)) throw e;
			expect(e.status).toBe(403);
		}
	});

	it('lets an administrator reach a bucket their group owns', () => {
		expect(() => assertBucketAccess(groupAdmin, bucket({}))).not.toThrow();
	});

	it('refuses an administrator a bucket another group owns with 403', () => {
		try {
			assertBucketAccess(groupAdmin, bucket({ ownerGroupId: 'g9' }));
			throw new Error('should have thrown');
		} catch (e) {
			if (!(e instanceof AdminError)) throw e;
			expect(e.status).toBe(403);
		}
	});

	it('lets a super administrator reach a bucket of any group', () => {
		expect(() =>
			assertBucketAccess(superAdmin, bucket({ ownerGroupId: 'g9' }))
		).not.toThrow();
	});
});
