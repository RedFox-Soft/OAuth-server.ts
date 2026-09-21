import { describe, it, expect, beforeEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { sessionFor } from '../admin_session.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);

const TAKEN_HOST = 'taken.e.ly';

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function createBucket(cookie: string, body: Record<string, unknown>) {
	const response = await app.handle(
		new Request('http://e.ly/admin/api/buckets', {
			method: 'POST',
			redirect: 'manual',
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
	return { status: response.status, message: await response.text() };
}

/**
 * @proves An address a bucket cannot be reached at, or that is not this deployment's to give, is
 * refused at the moment it is offered and with the rule it broke — and naming a hostname is an act of
 * the instance rather than of a group.
 */
describe('refusing an address that cannot work or should not exist (US2)', () => {
	let superCookie: string;

	beforeEach(async () => {
		await ensureAdminSeed();
		forgetBucketAddresses();
		superCookie = await cookieFor(['super_admin']);
		if (!(await getBucketStore().findByHost(TAKEN_HOST))) {
			await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'Taken',
				host: TAKEN_HOST
			});
		}
	});

	it('refuses a hostname supplied by an administrator who administers only a group', async () => {
		const projectAdmin = await cookieFor(['project_admin']);

		const { status } = await createBucket(projectAdmin, {
			name: 'Escalated',
			host: 'escalated.e.ly'
		});

		/* Names within the deployment's domain are the instance owner's to give. A group administrator
		 * who could claim one would reach out of their group and into whatever else that domain serves. */
		expect(status).toBe(403);
	});

	it('refuses a bucket given both a path segment and a hostname', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Both',
			slug: 'both',
			host: 'both.e.ly'
		});

		/* Refused, never resolved by precedence: a rule that silently prefers one leaves the operator who
		 * supplied the other believing it took effect. */
		expect(status).toBe(400);
		expect(message).toContain('not both');
	});

	it('refuses a bucket given no address at all', async () => {
		const { status } = await createBucket(superCookie, { name: 'Nameless' });

		expect(status).toBe(400);
	});

	it('refuses a hostname equal to the deployment own address', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Shadow',
			host: 'e.ly'
		});

		/* A bucket holding it would shadow the entire server. */
		expect(status).toBe(409);
		expect(message).toContain("deployment's own address");
	});

	it('refuses a hostname another bucket already holds, naming the holder', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Second',
			host: TAKEN_HOST
		});

		expect(status).toBe(409);
		expect(message).toContain('Taken');
	});

	/* The window the lookup above cannot cover. Two operators assigning one hostname both read "free"
	 * and both write, so the datastore's own constraint is what makes the guarantee true — and the
	 * loser of that race is owed the same refusal as the operator who was simply second, not an
	 * internal fault and a recorded defect. The stubbed lookup is the race: it answers "free" about a
	 * name that is held. */
	it('refuses with a conflict when the hostname is taken between the check and the write', async () => {
		const lookup = spyOn(getBucketStore(), 'findByHost').mockResolvedValue(
			undefined
		);

		try {
			const { status } = await createBucket(superCookie, {
				name: 'Racer',
				host: TAKEN_HOST
			});

			expect(status).toBe(409);
		} finally {
			lookup.mockRestore();
		}
	});

	it('refuses a value that is a URL rather than a hostname, saying what was wrong', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Url',
			host: 'https://acme.e.ly/login'
		});

		expect(status).toBe(400);
		expect(message).toContain('scheme');
	});

	/* Its own case rather than a second assertion on the one above: an operator who pastes the address
	 * bar gets a value with a scheme, one who pastes a link gets a value with a path, and being told
	 * "remove the scheme" about a value that has none is how a name takes three attempts. */
	it('refuses a value carrying a path, saying what was wrong', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Path',
			host: 'acme.e.ly/tenant'
		});

		expect(status).toBe(400);
		expect(message).toContain('path');
	});

	it('refuses a wildcard hostname', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Wild',
			host: '*.e.ly'
		});

		expect(status).toBe(400);
		expect(message).toContain('wildcard');
	});

	it('refuses a hostname with a space in it, saying what was wrong', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Spaced',
			host: 'acme .e.ly'
		});

		expect(status).toBe(400);
		expect(message).toContain('whitespace');
	});

	it('refuses a hostname carrying a port', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Ported',
			host: 'acme.e.ly:8443'
		});

		expect(status).toBe(400);
		expect(message).toContain('port');
	});

	it('refuses a single-label hostname that resolves only inside one network', async () => {
		const { status, message } = await createBucket(superCookie, {
			name: 'Bare',
			host: 'acme'
		});

		expect(status).toBe(400);
		expect(message).toContain('dot');
	});

	it('refuses a hostname the operator reserved for this deployment', async () => {
		const reserved = ApplicationConfig['buckets.reservedHostnames'] as string[];
		const restore = [...reserved];
		reserved.push('STATUS.e.ly');

		try {
			const { status, message } = await createBucket(superCookie, {
				name: 'Status',
				host: 'status.e.ly'
			});

			/* Compared in normalised form: a reservation typed in different case than the request would
			 * otherwise be a reservation that does not hold. */
			expect(status).toBe(409);
			expect(message).toContain('reserved for this deployment');
		} finally {
			reserved.length = 0;
			reserved.push(...restore);
		}
	});

	it('stores an accepted hostname in the form it is compared in', async () => {
		const host = `fine-${Math.floor(Math.random() * 1e6)}.e.ly`;
		const { status } = await createBucket(superCookie, {
			name: 'Fine',
			host: host.toUpperCase() + '.'
		});

		expect(status).toBe(201);

		/* Case folded and the trailing dot removed, or uniqueness is not uniqueness: two buckets that
		 * differ only in how the name was typed would both be created and a request would resolve to
		 * neither. */
		const stored = await getBucketStore().findByHost(host);
		expect(stored?.name).toBe('Fine');
	});
});
