import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { RESERVED_SUBDOMAIN_LABELS } from 'lib/consts/reserved_names.ts';
import { shaped } from 'test/shape.ts';
import {
	call,
	createProject,
	freshSlug,
	saveAddressForms,
	superAdministrator,
	teamOwner,
	type Caller
} from './admin.ts';

const Refusal = Type.Object({ message: Type.String() });
const Created = Type.Object({ _id: Type.String() });

let operator: Caller;

function messageOf(body: unknown): string {
	return shaped(Refusal, body).message;
}

/**
 * @proves A subdomain never lands on a name the operator keeps for their own services, on a label a browser
 * may render as other characters, or on a name another project already answers at — and a slug and the
 * subdomain it would become are one name, whichever form claims it first.
 */
describe('the names a project subdomain may not take', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'subdomain_projects' });
		await ensureAdminSeed();
		operator = await superAdministrator();
		await saveAddressForms(operator.cookie, 'both');
	});

	beforeEach(() => {
		forgetBucketAddresses();
	});

	afterEach(() => {
		ApplicationConfig['projects.reservedHostnames'] = [];
	});

	it('refuses every label kept for the operator’s own services, at create, naming the rule', async () => {
		const team = await teamOwner();
		const answers: [string, number, boolean][] = [];
		for (const label of RESERVED_SUBDOMAIN_LABELS) {
			const refused = await createProject(team, {
				slug: label,
				addressForm: 'subdomain'
			});
			/* A label that is also one of the server's own paths is refused by that rule first; either names it. */
			answers.push([
				label,
				refused.status,
				refused.status === 409 &&
					messageOf(refused.body).includes('is reserved for this')
			]);
		}

		expect(answers.filter(([, , named]) => !named)).toEqual([]);
	});

	it('refuses a label kept for the operator’s services to a super administrator too', async () => {
		const refused = await createProject(operator, {
			slug: 'www',
			addressForm: 'subdomain'
		});

		expect(refused.status).toBe(409);
	});

	it('refuses a subdomain whose full name is a reserved hostname', async () => {
		const slug = freshSlug('kept');
		ApplicationConfig['projects.reservedHostnames'] = [`${slug}.E.LY.`];

		const refused = await createProject(await teamOwner(), {
			slug,
			addressForm: 'subdomain'
		});

		expect(refused.status).toBe(409);
		expect(messageOf(refused.body)).toContain('reserved for this deployment');
	});

	it('refuses a label with hyphens in its third and fourth characters', async () => {
		const refused = await createProject(await teamOwner(), {
			slug: 'xn--80ak6aa92e',
			addressForm: 'subdomain'
		});

		expect(refused.status).toBe(400);
		expect(messageOf(refused.body)).toContain("'--'");
	});

	it('accepts the same label as a path, where nobody renders it', async () => {
		const created = await createProject(await teamOwner(), {
			slug: `xn--${Math.random().toString(36).slice(2, 8)}`
		});

		expect(created.status).toBe(201);
	});

	it('refuses a subdomain another project answers at as its hostname, naming that project', async () => {
		const slug = freshSlug('held');
		await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Holder',
			host: `${slug}.e.ly`
		});

		const refused = await createProject(await teamOwner(), {
			slug,
			addressForm: 'subdomain'
		});

		expect(refused.status).toBe(409);
		expect(messageOf(refused.body)).toContain('Holder');
	});

	it('refuses a hostname one label beneath the instance when that label is another project’s slug', async () => {
		const slug = freshSlug('pathed');
		await createProject(await teamOwner(), { slug });

		const refused = await createProject(operator, { host: `${slug}.e.ly` });

		expect(refused.status).toBe(409);
		expect(messageOf(refused.body)).toContain(
			'is the subdomain of the project'
		);
	});

	it('accepts a hostname two labels beneath the instance whatever the slugs', async () => {
		const slug = freshSlug('deep');
		await createProject(await teamOwner(), { slug });

		const created = await createProject(operator, {
			host: `login.${slug}.e.ly`
		});

		expect(created.status).toBe(201);
	});

	it('creates one project and refuses the other when two ask for one slug at once', async () => {
		const team = await teamOwner();
		const slug = freshSlug('race');

		const statuses = (
			await Promise.all([
				createProject(team, { slug, addressForm: 'subdomain' }),
				createProject(team, { slug, addressForm: 'subdomain' })
			])
		)
			.map((answer) => answer.status)
			.sort();

		expect(statuses).toEqual([201, 409]);
	});

	it('refuses, at an address change, every name it refuses at create', async () => {
		const team = await teamOwner();
		const created = await createProject(team, { slug: freshSlug('mover') });
		const id = shaped(Created, created.body)._id;

		const refused = await call(
			'POST',
			`/admin/api/projects/${id}/address`,
			team.cookie,
			{ slug: 'status', addressForm: 'subdomain' }
		);

		expect(refused.status).toBe(409);
	});
});
