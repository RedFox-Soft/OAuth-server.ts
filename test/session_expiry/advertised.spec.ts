import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { Type } from '@sinclair/typebox';
import bootstrap from '../test_helper.ts';
import { configStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { shaped } from 'test/shape.ts';
import {
	discoveryDocument,
	saveSettings,
	superAdminCookie
} from '../settings_apply/helpers.ts';

/* What a deployment that saved its claims setting before `session_expiry` was emitted holds. */
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
 * @proves A relying party can discover that the server says when to send the person back, on every
 * instance — including one whose operator saved a claims setting before it did.
 */
describe('what the server says about session_expiry', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'session_expiry' });
		resetAdminMemoryStores();
		await configStore.set({});
	});

	// The settings store outlives this file (test/amr/advertised.spec.ts gives the reason).
	afterAll(async () => {
		await configStore.set({});
	});

	it('advertises session_expiry among the supported claims', async () => {
		expect(await supportedClaims()).toContain('session_expiry');
	});

	it('advertises session_expiry after an administrator saves a claims setting that does not mention it', async () => {
		const saved = await saveSettings(await superAdminCookie(), {
			claims: STORED_BEFORE
		});
		expect(saved.status).toBe(200);

		expect(await supportedClaims()).toContain('session_expiry');
	});
});
