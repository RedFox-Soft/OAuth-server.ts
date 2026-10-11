import { describe, it, expect, beforeAll, afterEach } from 'bun:test';
import bootstrap from '../test_helper.ts';
import {
	adminAuditStore,
	getBucketStore,
	getGroupStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_CLIENT_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { isSuperAdmin } from 'lib/admin/super_admins.ts';
import { elysia } from 'lib/index.ts';
import type { FederationProvider } from 'lib/federation/types.ts';
import { idpStub } from '../federation/idp_stub.ts';
import {
	get,
	provider,
	signedInAccountIds,
	startInteraction,
	walk
} from '../federation/harness.ts';

const PASSWORD = 'correct horse battery';
let seq = 0;
const unique = (domain = 'corp.example') =>
	`admin-${Date.now()}-${(seq += 1)}@${domain}`;
/* One upstream subject per person, so a link made in one case never answers for another. */
const subjectOf = (email: string) => `upstream-${email}`;

async function withProviders(
	providers: FederationProvider[],
	fields: Record<string, unknown> = {}
) {
	await getBucketStore().update(ADMIN_BUCKET_ID, {
		federation: providers,
		...fields
	});
}

async function administrator(email: string) {
	return getUserStore(ADMIN_BUCKET_ID).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
}

async function upstream(origin: string) {
	const idp = await idpStub(origin);
	idp.expectDiscovery();
	return idp;
}

/* A sign-in to the console through the provider, as the person's browser walks it. */
async function signInThrough(
	idp: Awaited<ReturnType<typeof idpStub>>,
	email: string
) {
	const { uid, cookie } = await startInteraction(ADMIN_CLIENT_ID);
	const walked = await walk(uid, cookie, {
		idp,
		claims: { sub: subjectOf(email), email, email_verified: true }
	});
	return { uid, cookie, ...walked };
}

async function passwordProof(uid: string, cookie: string, email: string) {
	await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams({ username: email, password: PASSWORD })
		})
	);
}

/**
 * @proves Administrators sign in to the console through the identity providers of the administrators'
 * bucket: an existing administrator only after proving the account with its password, a new one only
 * while the console takes sign-ups, with a personal group and never the instance privilege.
 */
describe('signing in to the console through an identity provider', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin_federation' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	// The administrators' bucket outlives this file.
	afterEach(async () => {
		await withProviders([], { registrationOpen: false, passwordLogin: true });
	});

	it("the console sign-in page offers the Administrators bucket's enabled providers and not its disabled ones", async () => {
		await withProviders([
			provider('https://idp-console-page.test', {
				id: 'corp-sso',
				displayName: 'Corp SSO'
			}),
			provider('https://idp-console-off.test', {
				id: 'old-sso',
				displayName: 'Old SSO',
				enabled: false
			})
		]);

		const { uid, cookie } = await startInteraction(ADMIN_CLIENT_ID);
		const page = await get(`/ui/${uid}/login`, cookie);

		expect(page.text).toContain(`/ui/${uid}/federation/corp-sso/start`);
		expect(page.text).not.toContain('old-sso');
	});

	it('a linked administrator signs in through the provider', async () => {
		const origin = 'https://idp-console-linked.test';
		await withProviders([provider(origin, { emailTrusted: true })]);
		const email = unique();
		const admin = await administrator(email);
		await getUserStore(ADMIN_BUCKET_ID).update(admin._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: subjectOf(email),
					linkedAt: new Date()
				}
			]
		});

		await signInThrough(await upstream(origin), email);

		expect(signedInAccountIds()).toContain(admin._id);
	});

	it('a first sign-in matching an existing administrator links only after the password proof', async () => {
		const origin = 'https://idp-console-proof.test';
		await withProviders([provider(origin, { emailTrusted: true })]);
		const email = unique();
		const admin = await administrator(email);

		const { uid, cookie } = await signInThrough(await upstream(origin), email);
		expect(signedInAccountIds()).not.toContain(admin._id);
		expect(
			(await getUserStore(ADMIN_BUCKET_ID).find(admin._id))?.federated ?? []
		).toEqual([]);

		await passwordProof(uid, cookie, email);
		expect(
			(await getUserStore(ADMIN_BUCKET_ID).find(admin._id))?.federated
		).toEqual([expect.objectContaining({ providerId: 'acme-sso' })]);
	});

	/*
	 * Ordinary buckets link a second provider without asking; the console's does not, because the account
	 * behind the address may hold the instance privilege.
	 */
	it('an administrator who already holds an identity links another provider only after the password proof', async () => {
		const origin = 'https://idp-console-second.test';
		await withProviders([provider(origin, { emailTrusted: true })]);
		const email = unique();
		const admin = await administrator(email);
		await getUserStore(ADMIN_BUCKET_ID).update(admin._id, {
			federated: [
				{ providerId: 'other-sso', sub: 'elsewhere', linkedAt: new Date() }
			]
		});

		await signInThrough(await upstream(origin), email);

		expect(signedInAccountIds()).not.toContain(admin._id);
		expect(
			(await getUserStore(ADMIN_BUCKET_ID).find(admin._id))?.federated
		).toHaveLength(1);
	});

	it('a locked administrator is refused through a provider', async () => {
		const origin = 'https://idp-console-locked.test';
		await withProviders([provider(origin, { emailTrusted: true })]);
		const email = unique();
		const admin = await administrator(email);
		await getUserStore(ADMIN_BUCKET_ID).update(admin._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: subjectOf(email),
					linkedAt: new Date()
				}
			],
			lockedLocally: { at: new Date(), by: 'test', reason: 'compromised' }
		});

		await signInThrough(await upstream(origin), email);

		expect(signedInAccountIds()).not.toContain(admin._id);
	});

	it('with sign-up open and a provider allowed to create accounts, a first sign-in creates an administrator with a personal group and a sign-up entry in the audit trail', async () => {
		const origin = 'https://idp-console-create.test';
		await withProviders(
			[provider(origin, { emailTrusted: true, provisioning: 'jit' })],
			{ registrationOpen: true }
		);
		const email = unique();

		await signInThrough(await upstream(origin), email);

		const created = await getUserStore(ADMIN_BUCKET_ID).findByEmail(email);
		expect(created).not.toBeNull();
		const id = created?._id ?? '';
		expect(await getGroupStore().findPersonalFor(id)).not.toBeNull();
		expect(await isSuperAdmin(id)).toBe(false);
		const { entries } = await adminAuditStore.list({
			action: 'admin.register',
			targetId: id
		});
		expect(entries).toHaveLength(1);
	});

	it('with sign-up closed, no first federated sign-in creates an account, whatever the provider allows, and the person is told they have no console account', async () => {
		const origin = 'https://idp-console-closed.test';
		await withProviders(
			[provider(origin, { emailTrusted: true, provisioning: 'jit' })],
			{ registrationOpen: false }
		);
		const email = unique();

		const { callback } = await signInThrough(await upstream(origin), email);

		expect(await getUserStore(ADMIN_BUCKET_ID).findByEmail(email)).toBeNull();
		expect(callback.status).toBe(403);
		expect(callback.text).toContain('You have no console account');
	});

	it('a person from a domain the provider does not admit is neither created nor linked', async () => {
		const origin = 'https://idp-console-domain.test';
		await withProviders(
			[
				provider(origin, {
					emailTrusted: true,
					provisioning: 'jit',
					allowedEmailDomains: ['corp.example']
				})
			],
			{ registrationOpen: true }
		);
		const email = unique('other.example');

		await signInThrough(await upstream(origin), email);

		expect(await getUserStore(ADMIN_BUCKET_ID).findByEmail(email)).toBeNull();
	});
});
