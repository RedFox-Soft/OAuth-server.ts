import { describe, it, beforeAll, expect } from 'bun:test';

import {
	createEndUser,
	EndUserError,
	updateEndUser,
	type EndUserActor
} from 'lib/end_users/service.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';
import { defaultBucket } from './fixtures.ts';

const CONN_A: EndUserActor = { kind: 'connection', connectionId: 'conn-a' };
const CONN_B: EndUserActor = { kind: 'connection', connectionId: 'conn-b' };

async function provision(
	actor: EndUserActor,
	fields: { userName?: string; externalId?: string }
) {
	return createEndUser(
		await defaultBucket(),
		actor,
		{ id: nanoid(), email: `${nanoid()}@x.io`, ...fields },
		async () => {}
	);
}

async function refusal(operation: Promise<unknown>) {
	try {
		await operation;
	} catch (error) {
		if (error instanceof EndUserError) return error;
		throw error;
	}
	throw new Error('expected the change to be refused');
}

/*
 * Through the end-user service, because no public surface sets a username or an external identifier until
 * provisioning arrives (spec 069 part 2) — the only place these rules are observable today.
 */

/**
 * @proves An external identifier is scoped to the connection that issued it, and the sign-in address stays
 * unique when it changes (spec 069, FR-010, FR-013). The username and same-connection cases are proved at the
 * SCIM surface now (test/scim/users_create.spec.ts, test/scim/users_lifecycle.spec.ts).
 */
describe('provisioned identities in a bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('accepts the same external identifier from another connection', async () => {
		const externalId = nanoid();
		await provision(CONN_A, { externalId });

		const user = await provision(CONN_B, { externalId });

		expect(user).toMatchObject({ externalId, provisionedBy: 'conn-b' });
	});

	it('refuses an email change to an address another user in the bucket holds', async () => {
		const taken = await provision(CONN_A, {});
		const user = await provision(CONN_A, {});

		const error = await refusal(
			updateEndUser(
				await defaultBucket(),
				CONN_A,
				user._id,
				{ email: taken.email.toUpperCase() },
				async () => {}
			)
		);

		expect(error.status).toBe(409);
		expect(error.message).toBe('email already exists');
	});

	it('moves the sign-in address when the email changes to a free one', async () => {
		const user = await provision(CONN_A, {});
		const previous = user.email;
		const moved = `Moved-${nanoid()}@X.io`;

		await updateEndUser(
			await defaultBucket(),
			CONN_A,
			user._id,
			{ email: moved },
			async () => {}
		);

		const store = getUserStore((await defaultBucket())._id);
		expect((await store.findByEmail(moved))?._id).toBe(user._id);
		expect(await store.findByEmail(previous)).toBeNull();
	});
});
