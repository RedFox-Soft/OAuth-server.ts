import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	setSystemTime
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import {
	getBucketStore,
	getConnectedAccountStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { purgeAtOf } from 'lib/consts/bucket_deletion.ts';
import { findLink } from 'lib/connected_services/link.ts';
import { lockEndUser } from 'lib/end_users/service.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	Browser,
	addressedBucket,
	xsrfFrom
} from '../connected_apps/helpers.ts';
import {
	accountsOf,
	callback,
	signedInPerson
} from '../connected_services/harness.ts';
import { unique } from '../connected_services/stubs.ts';
import {
	connected,
	exchange,
	githubService,
	refused
} from '../upstream_tokens/harness.ts';
import { act, linkFor, locationOf, personAndAgent, read } from './harness.ts';

/**
 * @proves A connect link acts only for the person the agent's token named, at the project that made it, while it
 * lives, and only when that person presses its button on its own page; anyone else, any other address, an altered,
 * expired, replaced or used link changes nothing and learns nothing about that person.
 */
describe('who a connect link works for', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'connect_link' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		setSystemTime();
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function consentLink() {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const record = await connected(owner.accountId, service);
		const { path } = await linkFor(owner.signedIn, service);
		return { service, owner, record, path };
	}

	async function stillRefused(
		owner: Awaited<ReturnType<typeof personAndAgent>>,
		serviceId: string
	) {
		return refused(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: serviceId
			})
		).reason;
	}

	it('refuses another person who opens it, and names nobody', async () => {
		const { service, owner, path } = await consentLink();
		const other = await signedInPerson();

		const page = await read(other.browser, path);

		expect(page.status).toBe(403);
		expect(page.text).toContain('for another account');
		expect(page.text).not.toContain(owner.email);
		expect(await stillRefused(owner, service.id)).toBe('consent_required');
	});

	it('refuses another person who posts it with their own page’s value', async () => {
		const { service, owner, path } = await consentLink();
		const other = await consentLink();
		const xsrf = xsrfFrom(
			await (await other.owner.browser.request(other.path)).text()
		);

		const posted = await other.owner.browser.post(path, {
			action: 'connect',
			xsrf
		});

		expect(posted.status).toBe(403);
		expect(await stillRefused(owner, service.id)).toBe('consent_required');
	});

	it('is unknown at another project’s address', async () => {
		const { owner, path } = await consentLink();
		const slug = unique('elsewhere').toLowerCase();
		await addressedBucket(unique('bucket'), { slug });

		const page = await read(owner.browser, `/${slug}${path}`);

		expect(page.status).toBe(404);
		expect(page.text).toContain('no longer valid');
	});

	it('reads the same when expired, replaced or never made', async () => {
		const first = await consentLink();
		const replaced = first.path;
		/* The person disconnects meanwhile: the next refusal is a connect, which takes the slot. */
		await getConnectedAccountStore().destroy(
			DEFAULT_BUCKET_ID,
			first.record._id
		);
		const { path: current } = await linkFor(
			first.owner.signedIn,
			first.service
		);
		expect(current).not.toBe(replaced);
		const stranger = new Browser();

		const pages = [
			await read(stranger, replaced),
			await read(stranger, `/account/services/link/${unique('guess')}`)
		];
		setSystemTime(new Date(Date.now() + 31 * 60 * 1000));
		pages.push(await read(stranger, current));

		for (const page of pages) {
			expect(page.status).toBe(404);
			expect(page.text).toBe(pages[0].text);
		}
	});

	it('starts nothing when its person opens it once it was used', async () => {
		const { owner, record, path } = await consentLink();
		await act(owner.browser, path, {
			action: 'allow',
			connectedAccountId: record._id
		});

		const page = await read(owner.browser, path);

		expect(page.status).toBe(200);
		expect(page.text).toContain('already done');
		expect(page.html).not.toContain('name="xsrf"');
	});

	it('reads to anyone else, once used, like any other link of someone else’s', async () => {
		const { owner, record, path } = await consentLink();
		await act(owner.browser, path, {
			action: 'allow',
			connectedAccountId: record._id
		});
		const other = await signedInPerson();

		const page = await read(other.browser, path);

		expect(page.status).toBe(403);
		expect(page.text).not.toContain('already done');
	});

	it('carries no token, identifier or label in its address', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const record = await connected(owner.accountId, service);

		const { body, path } = await linkFor(owner.signedIn, service);
		const uri = present(body.connect_uri, 'a link');

		expect(new URL(uri).search).toBe('');
		expect(path).toMatch(/^\/account\/services\/link\/[A-Za-z0-9_-]{43}$/);
		for (const secret of [
			owner.accountId,
			owner.email,
			service.id,
			record.label,
			record._id,
			owner.signedIn.accessToken
		]) {
			expect(uri).not.toContain(secret);
		}
	});

	it('is refused for a person who can no longer sign in, and a lock ends it', async () => {
		const { owner, path } = await consentLink();
		const value = present(path.split('/').at(-1), 'the value');

		await lockEndUser(
			present(await getBucketStore().find(DEFAULT_BUCKET_ID), 'the project'),
			owner.accountId,
			{ by: 'an-administrator', reason: 'test' },
			async () => {}
		);
		const page = await read(owner.browser, path);

		expect(page.text).not.toContain('Allow');
		expect(await findLink(value)).toBeUndefined();
	});

	it('is refused while its project is being deleted', async () => {
		const { owner, path } = await consentLink();
		const scheduledAt = new Date();
		await getBucketStore().scheduleDeletion(DEFAULT_BUCKET_ID, {
			scheduledAt,
			purgeAt: purgeAtOf(scheduledAt),
			scheduledBy: { userId: 'an-administrator' }
		});
		forgetBucketAddresses();
		try {
			const page = await read(owner.browser, path);

			expect(page.status).toBe(404);
		} finally {
			await getBucketStore().cancelDeletion(DEFAULT_BUCKET_ID, new Date());
			forgetBucketAddresses();
		}
	});

	it('connects nothing when the provider’s answer arrives in another browser', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const { path } = await linkFor(owner.signedIn, service);
		const pressed = await act(owner.browser, path, { action: 'connect' });

		const answered = await callback(new Browser(), locationOf(pressed));

		expect(answered.status).toBe(403);
		expect(await accountsOf(owner.accountId)).toHaveLength(0);
	});

	it('changes nothing until its button is pressed', async () => {
		const { service, owner, path } = await consentLink();

		const page = await read(owner.browser, path);

		expect(page.status).toBe(200);
		expect(page.text).toContain('Allow');
		expect(await stillRefused(owner, service.id)).toBe('consent_required');
	});

	it('refuses a post without the page’s value, and one from another site', async () => {
		const { service, owner, record, path } = await consentLink();

		const without = await owner.browser.post(path, {
			action: 'allow',
			connectedAccountId: record._id,
			xsrf: 'not-the-value'
		});
		const crossSite = await act(
			owner.browser,
			path,
			{ action: 'allow', connectedAccountId: record._id },
			{ origin: 'https://attacker.example', 'sec-fetch-site': 'cross-site' }
		);

		expect(without.status).toBe(403);
		expect(crossSite.status).toBe(403);
		expect(await stillRefused(owner, service.id)).toBe('consent_required');
	});

	it('says so, and offers nothing, once its service was deleted', async () => {
		const { service, owner, path } = await consentLink();
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the project'
		);
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			connectedServices: (bucket.connectedServices ?? []).filter(
				(item) => item.id !== service.id
			)
		});

		const page = await read(owner.browser, path);

		expect(page.text).toContain('no longer offered');
		expect(page.html).not.toContain('name="xsrf"');
	});
});
