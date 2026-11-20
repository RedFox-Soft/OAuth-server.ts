import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { configStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import {
	AMR_FOR_METHOD,
	DISTINCTION_FOR_METHOD,
	SIGN_IN_METHODS
} from 'lib/consts/amr.ts';
import { SATISFIED_BY } from 'lib/consts/acr.ts';
import { shaped } from 'test/shape.ts';
import {
	discoveryDocument,
	saveSettings,
	superAdminCookie
} from '../settings_apply/helpers.ts';
import { Browser, amrOf, seedBucket, seedUser, signIn } from './flow.ts';

/*
 * The IANA "Authentication Method Reference Values" registry as of 2026-10-01: the twenty values of
 * RFC 8176 §2, and `pop` from OpenID Connect EAP ACR Values 1.0. This is the declaration the server's
 * vocabulary is checked against, not a copy of it — a relying party can only interpret a value it
 * finds here, or one it agreed with the operator beforehand, and this server agrees nothing.
 */
const REGISTERED = new Set([
	'face',
	'fpt',
	'geo',
	'hwk',
	'iris',
	'kba',
	'mca',
	'mfa',
	'otp',
	'pin',
	'pop',
	'pwd',
	'rba',
	'retina',
	'sc',
	'sms',
	'swk',
	'tel',
	'user',
	'vbm',
	'wia'
]);

/* What a deployment that saved its claims setting before `amr` was reported holds. */
const STORED_BEFORE = {
	acr: null,
	sid: null,
	auth_time: null,
	iss: null,
	openid: ['sub']
};

async function supportedClaims() {
	return shaped(
		Type.Object({ claims_supported: Type.Array(Type.String()) }),
		await discoveryDocument()
	).claims_supported;
}

/**
 * @proves A relying party can discover that the server reports authentication methods on every
 * instance — including one whose operator saved a claims setting before it did — every method
 * the server reports is one the registry defines, and `mfa` is reported exactly with the
 * multi-factor context, whichever way the person signed in.
 */
describe('what the server says about authentication methods', () => {
	let plainBucketId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'amr' });
		resetAdminMemoryStores();
		await configStore.set({});
		plainBucketId = await seedBucket('AMR advertised', ['amr-app']);
	});

	// The settings store outlives this file, and a later one comparing stored against running values
	// would read the claims saved here as a setting this instance has not applied.
	afterAll(async () => {
		await configStore.set({});
	});

	it('advertises amr among the supported claims', async () => {
		expect(await supportedClaims()).toContain('amr');
	});

	it('advertises and emits amr after an administrator saves a claims setting that does not mention it', async () => {
		const saved = await saveSettings(await superAdminCookie(), {
			claims: STORED_BEFORE
		});
		expect(saved.status).toBe(200);
		const email = await seedUser(plainBucketId);
		const auth = new AuthorizationRequest({
			client_id: 'amr-app',
			scope: 'openid'
		});

		const token = await auth.getToken(await signIn(new Browser(), auth, email));

		expect(await supportedClaims()).toContain('amr');
		expect(amrOf(token)).toEqual(['pwd']);
	});

	it('reports, for every way of signing in, only registered methods', () => {
		for (const way of SIGN_IN_METHODS) {
			for (const method of AMR_FOR_METHOD[way]) {
				expect(REGISTERED.has(method), `${way}: ${method}`).toBe(true);
			}
		}
	});

	// A relying party reads `mfa` as "two factors": it may appear only where the context says so, and must appear there.
	it('reports mfa, for every way of signing in, exactly when that way meets the multi-factor context', () => {
		for (const way of SIGN_IN_METHODS) {
			expect(AMR_FOR_METHOD[way].includes('mfa'), way).toBe(
				SATISFIED_BY.multi_factor.includes(DISTINCTION_FOR_METHOD[way])
			);
		}
	});
});
