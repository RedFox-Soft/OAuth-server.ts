import { Elysia } from 'elysia';

import { mcpClientPermissionStore } from '../../adapters/index.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';
import {
	isLoopbackRedirect,
	parseClientIdentifierUrl
} from '../../client_metadata_document/identifier.js';
import { fetchClientDocument } from '../../client_metadata_document/fetch.js';
import { validateClientDocument } from '../../client_metadata_document/validate.js';
import { PermitMcpClientBody, UpdateMcpClientBody } from './schema.js';

/*
 * Which client identities may reach the administrative MCP plane.
 *
 * Super-administrator only, and withheld from the agent surface entirely — an agent granting another
 * agent administrative access is a privilege-escalation path with no legitimate use a human could not
 * perform. `lib/mcp/catalogue.ts` names all four routes as exclusions with that reason.
 *
 * The list is empty on a new install and after an upgrade that changes nothing, which is what makes
 * "no deployment gains a new way in" true by construction rather than by a migration nobody runs.
 */

/*
 * The words an administrator reads before granting authority to a loopback-only client, and the words
 * the route answers with when they have not. One string, deliberately: the console renders this as the
 * acknowledgement it asks them to accept, so what they agreed to and what the route enforced cannot be
 * two different statements.
 */
export const LOOPBACK_ACKNOWLEDGEMENT =
	'This client offers only loopback redirect targets. Its document proves control of a domain, but it cannot prove which program on a machine will receive the authorization code — so anyone able to run a process on an administrator’s computer could receive it instead. Permit it only if you accept that.';

function validateValue(kind: 'identifier' | 'host', value: string): string {
	if (kind === 'identifier') {
		const parsed = parseClientIdentifierUrl(value);
		if (!parsed.ok) {
			throw new AdminError(
				400,
				'an identifier must be an https URL with a path component, no dot segments, no fragment and no embedded credentials'
			);
		}
		return parsed.url.href;
	}

	/*
	 * A bare host, checked by what it must NOT contain rather than by a hostname pattern — a pattern
	 * would have to encode the whole of IDN and would refuse something legitimate before it refused
	 * anything dangerous.
	 */
	if (/[/:@\s]/.test(value) || value.includes('.') === false) {
		throw new AdminError(
			400,
			'a host entry must be a bare hostname, with no scheme, port or path'
		);
	}
	return value.toLowerCase();
}

/*
 * Whether granting this entry needs the operator to accept the loopback risk.
 *
 * Retrieving the document is what makes the question answerable, and a document that cannot be
 * retrieved is refused rather than permitted on trust: an entry whose risk profile is unknown is one
 * nobody can be said to have accepted.
 *
 * A host-wide entry is not resolved this way. There is no single document behind it, so the honest
 * answer is that the risk is unknown for every identifier it will ever cover — the acknowledgement is
 * therefore always required.
 */
async function needsLoopbackAcknowledgement(
	kind: 'identifier' | 'host',
	value: string
): Promise<boolean> {
	if (kind === 'host') return true;

	/*
	 * Retrieved through the fetch and validation layers directly rather than through
	 * `resolveClientDocument`, which is gated on the capability that lets *unauthenticated* clients
	 * cause an outbound request. That gate is about who may make this server fetch a URL, and the
	 * answer for an authenticated super administrator establishing facts before granting administrative
	 * authority is plainly yes. The SSRF guards are the same either way — they live in the fetch layer,
	 * not in the gate.
	 *
	 * A permission may therefore be granted while the capability is off. That is deliberate: the entry
	 * is a standing decision, inert until document identifiers are accepted at all, exactly as the
	 * reserved client's project membership is inert until the MCP surface is switched on.
	 */
	const retrieved = await fetchClientDocument(value);
	if (!retrieved.ok) {
		throw new AdminError(
			400,
			`could not retrieve the client description document at that identifier (${retrieved.reason})`
		);
	}

	const validated = validateClientDocument(retrieved.body, value);
	if (!validated.ok) {
		throw new AdminError(
			400,
			`the document at that identifier is not a valid client description (${validated.reason})`
		);
	}

	const redirectUris = validated.metadata.redirectUris;
	if (!Array.isArray(redirectUris) || redirectUris.length === 0) return true;
	return redirectUris.every(
		(uri) => typeof uri === 'string' && isLoopbackRedirect(uri)
	);
}

export const mcpClientRoutes = new Elysia({ name: 'admin-mcp-clients' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/mcp/clients', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return mcpClientPermissionStore.list();
	})
	.post(
		'/admin/api/mcp/clients',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');

			const value = validateValue(body.kind, body.value);
			if (await mcpClientPermissionStore.find(value)) {
				throw new AdminError(409, 'that identity is already permitted');
			}

			const loopbackOnly = await needsLoopbackAcknowledgement(body.kind, value);
			if (loopbackOnly && body.acknowledgeLoopbackRisk !== true) {
				throw new AdminError(409, LOOPBACK_ACKNOWLEDGEMENT, {
					acknowledgementRequired: true
				});
			}

			await recordAdminAudit(ctx, 'mcp.client.permit', value, {
				attributes: Object.keys(body)
			});

			const entry = await mcpClientPermissionStore.create({
				_id: value,
				kind: body.kind,
				requireKeyProof: body.requireKeyProof,
				loopbackAcknowledged: loopbackOnly,
				...(loopbackOnly ? { acknowledgedBy: ctx.userId } : {})
			});
			set.status = 201;
			return entry;
		},
		{ body: PermitMcpClientBody }
	)
	.patch(
		'/admin/api/mcp/clients/:entryId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');

			const entryId = decodeURIComponent(params.entryId);
			if (!(await mcpClientPermissionStore.find(entryId))) {
				throw new AdminError(404, 'no such permitted identity');
			}

			await recordAdminAudit(ctx, 'mcp.client.update', entryId, {
				attributes: Object.keys(body)
			});

			return mcpClientPermissionStore.update(entryId, body);
		},
		{ body: UpdateMcpClientBody }
	)
	.delete('/admin/api/mcp/clients/:entryId', async ({ admin, params, set }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');

		const entryId = decodeURIComponent(params.entryId);
		if (!(await mcpClientPermissionStore.find(entryId))) {
			throw new AdminError(404, 'no such permitted identity');
		}

		await recordAdminAudit(ctx, 'mcp.client.withdraw', entryId, {});

		await mcpClientPermissionStore.destroy(entryId);
		set.status = 204;
		return null;
	});
