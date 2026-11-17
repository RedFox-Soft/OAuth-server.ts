import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { agentFor, tool } from '../behind_proxy/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { resetStoresForTests } from 'lib/adapters/index.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import {
	PersonBrowser,
	WRONG,
	from,
	person,
	project,
	signIn,
	typePassword
} from '../person_activity/helpers.ts';
import {
	LookupPage,
	batchOf,
	foxtrust,
	lookupsOf,
	seedFoxTrustKey,
	type FoxTrustFake
} from './helpers.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { shaped } from '../shape.ts';

let fake: FoxTrustFake;
let cookie: string;
let bucketId: string;

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

/* Each case is a server of its own: no key, nothing looked up yet. */
beforeEach(async () => {
	resetStoresForTests();
	forgetLookupsForTests();
	cookie = await adminCookie();
	bucketId = await project();
	fake = foxtrust();
	from('203.0.113.7');
});

afterEach(() => {
	ApplicationConfig['addressLookup.enabled'] = true;
});

async function signedInPage() {
	const anna = await person(bucketId);
	await signIn(anna.email);
	return lookupsOf(cookie, bucketId, anna.accountId, { kind: 'signIn' });
}

/**
 * @proves A row without an owner and location says why, as far as the server knows: lookups turned off, no FoxTrust
 * key yet, or today's lookups used up (specs/136 US1 scenario 5, FR-009).
 */
describe('a row without owner and location says why', () => {
	it('says lookups are turned off while the setting is off', async () => {
		await seedFoxTrustKey();
		ApplicationConfig['addressLookup.enabled'] = false;

		const page = await signedInPage();
		expect([page.rows[0].lookup, page.lookupState]).toEqual([null, 'off']);
	});

	it('says there is no key yet while none is held', async () => {
		const page = await signedInPage();

		expect([page.rows[0].lookup, page.lookupState]).toEqual([null, 'no-key']);
	});

	it("says today's lookups are used up after FoxTrust said so", async () => {
		await seedFoxTrustKey();
		fake.batch = (ips) =>
			batchOf(
				ips.map((ip) => ({ ip, error: 'quota' })),
				0
			);

		const page = await signedInPage();
		expect([page.rows[0].lookup, page.lookupState]).toEqual([null, 'used-up']);
	});
});

/**
 * @proves An agent reading a person's activity gets the same owner and location an administrator reads (specs/136 US1
 * scenario 6).
 */
describe("an agent reading a person's activity", () => {
	it('gets the owner and location of each address', async () => {
		await seedFoxTrustKey();
		const bob = await person(bucketId);
		await typePassword(new PersonBrowser(), bob.email, WRONG);
		await lookupsOf(cookie, bucketId, bob.accountId);

		const reader = await createAdministrator('super', `agent-${nanoid()}@x.io`);
		const answer = await tool(
			await agentFor(reader),
			'project_user_activity_list',
			{
				id: bucketId,
				uid: bob.accountId
			}
		);
		const page = shaped(LookupPage, answer.result?.structuredContent?.result);
		expect(page.rows.map((row) => row.lookup?.city)).toEqual(['Munich']);
	});
});
