import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterAll
} from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { consenting } from '../admin/sign_in_consent.ts';
import { call, superAdmin, type Caller } from './admin.ts';

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Console',
	fromEmail: 'console@example.test'
};
const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

const REFUSAL =
	'administrators can sign up only with email verification on: turn verification on in the same change';

function patchAdministrators(operator: Caller, body: Record<string, unknown>) {
	return consenting((consent) =>
		call('PATCH', `/admin/api/projects/${ADMIN_BUCKET_ID}`, operator.cookie, {
			...body,
			...consent
		})
	);
}

async function auditCount(): Promise<number> {
	return (await adminAuditStore.list({ action: 'bucket.update' })).total;
}

/**
 * @proves The administrators' project cannot be saved with sign-up open and email verification off — by opening
 * sign-up, or by turning verification off while it is open — and opening both together is accepted; nothing is
 * recorded for a refused change.
 */
describe("sign-up on the administrators' project", () => {
	let operator: Caller;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tenant_hardening' });
		await ensureAdminSeed();
		await getSmtpSettingsStore().set(MAIL);
	});

	beforeEach(async () => {
		operator = await superAdmin();
		// Requiring verification is accepted only from someone who has proven their own address.
		await getUserStore(ADMIN_BUCKET_ID).update(operator.user._id, {
			verified: true
		});
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			registrationOpen: false,
			emailVerificationRequired: false
		});
	});

	afterAll(async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			registrationOpen: false,
			emailVerificationRequired: false
		});
		await getSmtpSettingsStore().set(NO_MAIL);
	});

	it('refuses opening sign-up while verification is off, and records nothing', async () => {
		const before = await auditCount();

		const answer = await patchAdministrators(operator, {
			registrationOpen: true
		});

		expect(answer.status).toBe(409);
		expect((answer.body as { message: string }).message).toBe(REFUSAL);
		expect(
			(await getBucketStore().find(ADMIN_BUCKET_ID))?.registrationOpen
		).toBe(false);
		expect(await auditCount()).toBe(before);
	});

	it('accepts opening sign-up together with verification, with no warning', async () => {
		const answer = await patchAdministrators(operator, {
			registrationOpen: true,
			emailVerificationRequired: true
		});

		expect(answer.status).toBe(200);
		expect(answer.body).not.toHaveProperty('advisory');
		const saved = await getBucketStore().find(ADMIN_BUCKET_ID);
		expect(saved?.registrationOpen).toBe(true);
		expect(saved?.emailVerificationRequired).toBe(true);
	});

	it('refuses turning verification off while sign-up is open', async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			registrationOpen: true,
			emailVerificationRequired: true
		});

		const answer = await patchAdministrators(operator, {
			emailVerificationRequired: false
		});

		expect(answer.status).toBe(409);
		expect((answer.body as { message: string }).message).toBe(REFUSAL);
	});

	it('accepts closing sign-up and turning verification off in one change', async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			registrationOpen: true,
			emailVerificationRequired: true
		});

		const answer = await patchAdministrators(operator, {
			registrationOpen: false,
			emailVerificationRequired: false
		});

		expect(answer.status).toBe(200);
	});
});
