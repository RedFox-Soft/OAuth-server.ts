import { Elysia } from 'elysia';

import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';
import { getKeyringStateStore } from '../../adapters/index.js';
import { activeKeyring } from '../../sealing/keyring.js';
import { generateAndPlaceKeyring } from '../../sealing/generate.js';
import { keyringStatus } from '../../sealing/status.js';
import { KeyringGeneratedResponse, KeyringStatusResponse } from './schema.js';

/*
 * Encryption at rest (specs/116): its status for super administrators and agents, and the two actions only a
 * person can take — generating a keyring, whose answer is key material, and attesting that they stored it.
 * Both actions are withheld from MCP (lib/mcp/catalogue.ts says why).
 */
export const keyringRoutes = new Elysia({ name: 'admin-keyring' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/keyring',
		async ({ admin }) => {
			assertSuperAdmin(assertAuth(admin));
			return keyringStatus();
		},
		{ response: { 200: KeyringStatusResponse } }
	)
	.post(
		'/admin/api/keyring',
		async ({ admin, set }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			if (activeKeyring()) {
				throw new AdminError(
					409,
					'a keyring is already in use; rotate it with the keyring command instead'
				);
			}
			await recordAdminAudit(ctx, 'keyring.generate', 'keyring');
			const placement = await generateAndPlaceKeyring(ctx.userId);
			set.status = 201;
			return placement;
		},
		{ response: { 201: KeyringGeneratedResponse } }
	)
	.post(
		'/admin/api/keyring/backup-confirmation',
		async ({ admin, set }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			const store = getKeyringStateStore();
			const state = await store.read();
			if (!activeKeyring() && !state?.generated) {
				throw new AdminError(409, 'no keyring has been generated or supplied');
			}
			await recordAdminAudit(ctx, 'keyring.backup.confirm', 'keyring');
			await store.patch({
				backupConfirmed: { at: new Date().toISOString(), by: ctx.userId }
			});
			set.status = 204;
			return null;
		}
	);
