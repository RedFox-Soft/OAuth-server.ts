import { describe, it, expect } from 'bun:test';

import { documentOf } from 'lib/adapters/documents.ts';
import {
	AdminSession,
	ErrorGroup,
	Group,
	GroupInvitation
} from 'lib/adapters/types.ts';

const stamp = '2026-09-28T10:00:00.000Z';

/**
 * @proves A store document read back from a datastore is the shape its schema declares or the read
 * fails: dates a jsonb round trip turned into strings come back as dates exactly where the schema
 * declares them and nowhere else, an optional member MongoDB stored as null for undefined reads as
 * absent, and a document that does not match refuses to pass as the type, naming the store it came from.
 */
describe('stored documents are checked against their schema on the way out', () => {
	it('restores the dates a jsonb round trip turned into strings', () => {
		const group = documentOf('groups', Group, {
			_id: 'g-1',
			name: stamp,
			kind: 'regular',
			members: [{ userId: 'u-1', role: 'owner' }],
			createdAt: stamp,
			updatedAt: stamp
		});

		expect(group.createdAt).toBeInstanceOf(Date);
		expect(group.createdAt.toISOString()).toBe(stamp);
		// Text that happens to parse as a date stays text: only the schema names a date field.
		expect(group.name).toBe(stamp);
	});

	it('restores a nullable date and a nested one, and leaves null as null', () => {
		const invitation = documentOf('groupInvitations', GroupInvitation, {
			_id: 'i-1',
			groupId: 'g-1',
			email: 'a@example.com',
			role: 'member',
			invitedBy: 'u-1',
			tokenHash: 'h',
			expiresAt: stamp,
			acceptedAt: null,
			createdAt: stamp
		});
		expect(invitation.expiresAt).toBeInstanceOf(Date);
		expect(invitation.acceptedAt).toBeNull();

		const group = documentOf('errorGroups', ErrorGroup, {
			_id: 'e-1',
			fingerprint: 'f',
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth',
			route: '/token',
			method: 'POST',
			origin: { file: 'a.ts', line: 1, frame: 'x' },
			message: 'm',
			occurrences: 1,
			firstSeenAt: stamp,
			lastSeenAt: stamp,
			expiresAt: stamp,
			samples: [
				{
					reference: 'r',
					at: stamp,
					clientId: null,
					actor: null,
					scope: null,
					requestId: null,
					origin: null,
					userAgent: null,
					submittedFields: []
				}
			]
		});
		expect(group.samples[0]?.at).toBeInstanceOf(Date);
	});

	/*
	 * The MongoDB driver stores `undefined` as null, so an admin session signed in without a refresh
	 * token holds `refreshToken: null` — every console session does. Read as the absence it was written
	 * as, the session is usable; checked as written, it would refuse every console sign-in.
	 */
	it('reads an optional member stored as null as absent, and keeps a nullable one', () => {
		const session = documentOf('adminSession', AdminSession, {
			_id: 's-1',
			userId: 'u-1',
			bucketId: 'b-1',
			activeGroupId: 'g-1',
			tokens: { accessToken: 'a', idToken: 'i', refreshToken: null },
			createdAt: stamp,
			expiresAt: stamp,
			absoluteExpiresAt: stamp
		});
		expect(session.tokens).toEqual({ accessToken: 'a', idToken: 'i' });

		const invitation = documentOf('groupInvitations', GroupInvitation, {
			_id: 'i-2',
			groupId: 'g-1',
			email: 'a@example.com',
			role: 'member',
			invitedBy: 'u-1',
			tokenHash: 'h',
			expiresAt: stamp,
			acceptedAt: null,
			createdAt: stamp
		});
		expect(invitation).toHaveProperty('acceptedAt', null);
	});

	it('refuses a document that does not match, naming its store', () => {
		expect(() =>
			documentOf('groups', Group, {
				_id: 'g-2',
				name: 'broken',
				kind: 'regular',
				members: 'nobody',
				createdAt: stamp,
				updatedAt: stamp
			})
		).toThrow(
			/^groups: a stored document does not match its schema at '\/members'/
		);
	});
});
