import { describe, it, expect } from 'bun:test';

import {
	STORAGE_INVENTORY,
	USER_AREA_PREFIX,
	areaForBucket,
	areaNamed,
	indexesFor,
	userAreaFor
} from 'lib/consts/storage_inventory.js';

// Which areas are reaped, pinned exactly rather than merely checked for staleness.
//
// The two failures this guards are opposite and both silent. An area that should expire and does not
// grows without bound — expired verification challenges accumulating forever is the defect that
// prompted this feature. An area that should NOT expire but does deletes production data: clients,
// projects and buckets all carried an expiry index before this table, harmless only because they
// never write the field it keys on. Neither shows up in a functional test.

const REAPED_ON_EXPIRES_AT = [
	'AccessToken',
	'AuthorizationCode',
	'BackchannelAuthenticationRequest',
	'ClientCredentials',
	'DeviceCode',
	'Grant',
	'InitialAccessToken',
	'Interaction',
	'PushedAuthorizationRequest',
	'RefreshToken',
	'RegistrationAccessToken',
	'ReplayDetection',
	'Session',
	'VerificationChallenge',
	'VerificationResend',
	'adminSession'
];

const PERMANENT = [
	'Client',
	'jwks',
	'projects',
	'userBuckets',
	'adminAudit',
	'serviceConfig',
	USER_AREA_PREFIX
];

describe('storage inventory: expiry', () => {
	it('reaps exactly the areas whose records carry an expiry', () => {
		const reaped = STORAGE_INVENTORY.filter((area) => area.reaped !== null).map(
			(area) => area.name
		);

		expect(reaped.sort()).toEqual([...REAPED_ON_EXPIRES_AT].sort());
	});

	it('never reaps an area holding permanent records', () => {
		const permanent = STORAGE_INVENTORY.filter(
			(area) => area.reaped === null
		).map((area) => area.name);

		expect(permanent.sort()).toEqual([...PERMANENT].sort());
	});

	// Accounts for every area, so a new one cannot be added without landing in one of the two lists
	// above and forcing the author to decide which.
	it('classifies every inventoried area', () => {
		expect(REAPED_ON_EXPIRES_AT.length + PERMANENT.length).toBe(
			STORAGE_INVENTORY.length
		);
	});

	it('reaps on expiresAt, the field the adapter writes', () => {
		const fields = new Set(
			STORAGE_INVENTORY.filter((area) => area.reaped !== null).map(
				(area) => area.reaped
			)
		);

		expect([...fields]).toEqual(['expiresAt']);
	});

	it('derives an immediate-expiry index for a reaped area', () => {
		const specs = indexesFor(areaNamed('Session'));

		expect(specs).toContainEqual({
			key: { expiresAt: 1 },
			expireAfterSeconds: 0
		});
	});

	it('derives no expiry index for a permanent area', () => {
		expect(indexesFor(areaNamed('Client'))).toEqual([]);
	});

	// The admin audit trail is required to be immutable, so this one is worth its own assertion
	// rather than resting on the list above. Each index serves one shape the read surface queries;
	// what matters here is that not one of them can remove an entry.
	it('leaves the admin audit trail permanent and indexed for every read shape', () => {
		const audit = areaNamed('adminAudit');
		const specs = indexesFor(audit);

		expect(audit.reaped).toBeNull();
		expect(specs).toEqual([
			{ key: { timestamp: 1, _id: 1 } },
			{ key: { actorId: 1, timestamp: 1 } },
			{ key: { actorEmail: 1, timestamp: 1 } },
			{ key: { action: 1, timestamp: 1 } },
			{ key: { targetType: 1, targetId: 1, timestamp: 1 } },
			{ key: { targetScope: 1, timestamp: 1 } }
		]);
		expect(
			specs.some((spec) => spec.expireAfterSeconds !== undefined)
		).toBeFalse();
		expect(specs.some((spec) => spec.unique === true)).toBeFalse();
	});
});

describe('storage inventory: per-bucket user areas', () => {
	it('composes a bucket area name from the prefix', () => {
		expect(userAreaFor('abc')).toBe('user_abc');
		expect(userAreaFor('redfox')).toBe('user_redfox');
	});

	it('constrains a bucket area with a unique email index and no expiry', () => {
		const area = areaForBucket('abc');

		expect(area.name).toBe('user_abc');
		expect(area.reaped).toBeNull();
		expect(indexesFor(area)).toEqual([{ key: { email: 1 }, unique: true }]);
	});

	// Uniqueness is per collection, so per bucket. Two buckets holding the same address is legitimate;
	// one bucket holding it twice is the race this closes.
	it('scopes uniqueness per bucket', () => {
		expect(areaForBucket('one').name).not.toBe(areaForBucket('two').name);
	});
});
