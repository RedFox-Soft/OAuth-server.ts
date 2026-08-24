import type { TSchema } from 'elysia';

import {
	type AuditAction,
	type AuditedMethod
} from '../consts/admin_audit_routes.js';
import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody
} from '../admin/projects/schema.js';
import { CreateClientBody, UpdateClientBody } from '../admin/clients/schema.js';
import { CreateAdminBody, UpdateAdminBody } from '../admin/users/schema.js';
import { CreateBucketBody, UpdateBucketBody } from '../admin/buckets/schema.js';
import {
	CreateEndUserBody,
	UpdateEndUserBody,
	ResetPasswordBody
} from '../admin/users-end/schema.js';
import {
	CreateProviderBody,
	UpdateProviderBody
} from '../admin/federation/schema.js';
import { UpdateSettingsBody } from '../admin/settings/schema.js';
import { UpdateSmtpBody } from '../admin/settings/smtp/schema.js';
import { GenerateKeyBody } from '../admin/jwks/schema.js';
import { AuditQuery } from '../admin/audit/schema.js';

/*
 * THE published surface of the administrative MCP control plane: one entry per tool, mapped to the one
 * admin route that performs it.
 *
 * Load-bearing, not documentation — the same technique `lib/consts/admin_audit_routes.ts` uses, for the
 * same reason its comment gives: forgetting is the failure mode, so forgetting has to fail the suite.
 *
 *  - `McpToolName` is derived from this table, so a tool name absent from it cannot compile at the
 *    registration site.
 *  - `action` is typed as `AuditAction`, so a tool cannot claim an audit action the audit table does not
 *    declare, and cannot mistype one.
 *  - `test/mcp/catalogue_drift.spec.ts` compares the table against the mounted admin route set in both
 *    directions, so a new admin route is either published, named as an exclusion, or a test failure.
 *
 * Input schemas are the *same objects* the admin routes validate against (`lib/admin/<group>/schema.ts`), so
 * the schema an agent reads to build a call cannot drift from the schema the route enforces. That is
 * why this module imports schema modules and never route modules: a route module reaches the adapters
 * and from there `lib/adapters/mongodb/db.ts`, which connects at import time and is unloadable under
 * test. Same import discipline as the audit table.
 *
 * Paths are written in Elysia's declaration form so they compare directly against `elysia.routes`.
 * Matching is exact on (method, path), never a prefix test: `POST /admin/api/buckets` and
 * `POST /admin/api/buckets/:id/users` are different operations on different entities.
 */

export type Consequence = 'read' | 'ordinary' | 'high';

export interface McpTool {
	readonly tool: string;
	readonly method: 'GET' | AuditedMethod;
	readonly path: string;
	/* The audit action the underlying route records. `null` for reads, which record nothing. */
	readonly action: AuditAction | null;
	readonly consequence: Consequence;
	/*
	 * Documentation and tool annotation only — NEVER the enforcement point. Enforcement stays in the
	 * handler's own `assertRole`, which the tool reaches by re-dispatch. Present so a description can
	 * tell an agent what it needs, and so a drift test can compare it against the handler.
	 *
	 * `null` covers two different things on purpose: a route open to any authenticated administrator,
	 * and a route that is scope-filtered rather than role-gated (`bucket_list` returns the buckets the
	 * caller manages; `project_list` likewise). Neither refuses by role, so neither names one.
	 */
	readonly requiredRole: 'super_admin' | null;
	readonly bodySchema: TSchema | null;
	readonly querySchema: TSchema | null;
	readonly pathParams: readonly string[];
	/*
	 * Argument name to use for a path parameter whose declaration name collides with a body field.
	 *
	 * A tool takes one flat argument object, so `:id` and a body property called `id` cannot both be
	 * `id` — one silently wins and the other is dropped. That is not hypothetical: the federation
	 * provider create route is `/admin/api/buckets/:id/federation` while its body carries the
	 * provider's own `id`, so the provider id vanished and every call failed validation until this
	 * existed. `test/mcp/catalogue_drift.spec.ts` now refuses any tool whose final argument names
	 * collide, so the next such route fails the suite instead of shipping broken.
	 */
	readonly pathArgs?: Readonly<Record<string, string>>;
	readonly summary: string;
}

/* The argument name a path parameter is addressed by, after any alias. */
export function pathArgName(tool: McpTool, param: string): string {
	return tool.pathArgs?.[param] ?? param;
}

const catalogue = [
	/* ---------------------------------------------------------------- reads (15) */
	{
		tool: 'whoami',
		method: 'GET',
		path: '/admin/api/me',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The administrator this agent is acting as: their id, email, roles, and the projects they manage.'
	},
	{
		tool: 'project_list',
		method: 'GET',
		path: '/admin/api/projects',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'Every project a super-administrator can see, or just the projects the caller manages.'
	},
	{
		tool: 'project_get',
		method: 'GET',
		path: '/admin/api/projects/:id',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'One project: name, slug, managers, assigned user bucket, client ids, and CORS origins.'
	},
	{
		tool: 'client_list',
		method: 'GET',
		path: '/admin/api/projects/:id/clients',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'The OAuth clients registered in a project. Never returns a client secret.'
	},
	{
		tool: 'client_get',
		method: 'GET',
		path: '/admin/api/projects/:id/clients/:clientId',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'clientId'],
		summary:
			'One OAuth client: redirect URIs, grant types, auth method, and other registered metadata. Never returns its secret — a secret is shown once at creation or rotation and is not readable afterwards.'
	},
	{
		tool: 'admin_list',
		method: 'GET',
		path: '/admin/api/admins',
		action: null,
		consequence: 'read',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary: 'The administrator accounts of this instance, with their roles.'
	},
	{
		tool: 'bucket_list',
		method: 'GET',
		path: '/admin/api/buckets',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The user buckets: every one for a super-administrator, otherwise those the caller manages. The reserved administrator bucket is never listed.'
	},
	{
		tool: 'bucket_get',
		method: 'GET',
		path: '/admin/api/buckets/:id',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'One user bucket: its name, roles, managers, and registration and verification settings.'
	},
	{
		tool: 'bucket_user_list',
		method: 'GET',
		path: '/admin/api/buckets/:id/users',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary: 'The end-user accounts held in one bucket.'
	},
	{
		tool: 'federation_provider_list',
		method: 'GET',
		path: '/admin/api/buckets/:id/federation',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'The upstream identity providers configured on a bucket. Never returns a provider client secret.'
	},
	{
		tool: 'federation_identity_list',
		method: 'GET',
		path: '/admin/api/buckets/:id/users/:uid/identities',
		action: null,
		consequence: 'read',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'The upstream identities linked to one end-user account, by provider.'
	},
	{
		tool: 'settings_get',
		method: 'GET',
		path: '/admin/api/settings',
		action: null,
		consequence: 'read',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The editable server settings, with the catalogue describing each one and its current value.'
	},
	{
		tool: 'smtp_settings_get',
		method: 'GET',
		path: '/admin/api/settings/smtp',
		action: null,
		consequence: 'read',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The outbound mail settings. The password is never returned, only whether one is set.'
	},
	{
		tool: 'jwks_list',
		method: 'GET',
		path: '/admin/api/jwks',
		action: null,
		consequence: 'read',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The signing keys, each with its status, plus whether a restart is needed to apply pending changes. Public key material only — private components are never returned.'
	},
	{
		tool: 'audit_list',
		method: 'GET',
		path: '/admin/api/audit',
		action: null,
		consequence: 'read',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: AuditQuery,
		pathParams: [],
		summary:
			'The administrative audit trail, newest first, filterable by actor, action, target, surface and time window. Filter `viaSurface=mcp` for actions taken through an agent. An entry means an authorized actor reached the point of applying a change, not that the change took effect.'
	},

	/* ------------------------------------------------ writes: projects (3) */
	{
		tool: 'project_create',
		method: 'POST',
		path: '/admin/api/projects',
		action: 'project.create',
		consequence: 'ordinary',
		requiredRole: 'super_admin',
		bodySchema: CreateProjectBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Create a project: the container an instance groups OAuth clients into, with its own managers and CORS origins. A project has no user bucket until one is assigned.'
	},
	{
		tool: 'project_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id',
		action: 'project.update',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: UpdateProjectBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Change a project's name, managers, or CORS origins. An invalid origin refuses the whole list rather than applying part of it."
	},
	{
		tool: 'project_bucket_assign',
		method: 'PUT',
		path: '/admin/api/projects/:id/bucket',
		action: 'project.bucket.assign',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: SetBucketBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Assign the user bucket whose accounts this project’s clients authenticate against.'
	},

	/* ------------------------------------------------- writes: clients (4) */
	{
		tool: 'client_create',
		method: 'POST',
		path: '/admin/api/projects/:id/clients',
		action: 'client.create',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: CreateClientBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Register an OAuth client in a project. A confidential client’s generated secret is returned exactly once, here, and is never readable again.'
	},
	{
		tool: 'client_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/clients/:clientId',
		action: 'client.update',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: UpdateClientBody,
		querySchema: null,
		pathParams: ['id', 'clientId'],
		summary:
			"Change a client's registered metadata — redirect URIs, grant types, and the rest."
	},
	{
		tool: 'client_secret_rotate',
		method: 'POST',
		path: '/admin/api/projects/:id/clients/:clientId/secret',
		action: 'client.secret.rotate',
		consequence: 'high',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'clientId'],
		summary:
			'Issue a new secret for a confidential client and invalidate the old one. The new secret is returned exactly once. Anything still using the old secret stops working immediately.'
	},
	{
		tool: 'client_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/clients/:clientId',
		action: 'client.delete',
		consequence: 'high',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'clientId'],
		summary:
			'Permanently delete an OAuth client and revoke what was issued to it. Irreversible.'
	},

	/* -------------------------------------------- writes: administrators (3) */
	{
		tool: 'admin_create',
		method: 'POST',
		path: '/admin/api/admins',
		action: 'admin.create',
		consequence: 'ordinary',
		requiredRole: 'super_admin',
		bodySchema: CreateAdminBody,
		querySchema: null,
		pathParams: [],
		summary: 'Create an administrator account.'
	},
	{
		tool: 'admin_update',
		method: 'PATCH',
		path: '/admin/api/admins/:id',
		action: 'admin.update',
		consequence: 'ordinary',
		requiredRole: 'super_admin',
		bodySchema: UpdateAdminBody,
		querySchema: null,
		pathParams: ['id'],
		summary: "Change an administrator's roles or details."
	},
	{
		tool: 'admin_deactivate',
		method: 'DELETE',
		path: '/admin/api/admins/:id',
		action: 'admin.deactivate',
		consequence: 'high',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Deactivate an administrator: the account is kept but can no longer sign in. Refused for the last active super-administrator.'
	},

	/* ------------------------------------------------- writes: buckets (2) */
	{
		tool: 'bucket_create',
		method: 'POST',
		path: '/admin/api/buckets',
		action: 'bucket.create',
		consequence: 'ordinary',
		requiredRole: 'super_admin',
		bodySchema: CreateBucketBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Create a user bucket. A bucket cannot be created unreachable: at creation it has no providers, so password login cannot be switched off.'
	},
	{
		tool: 'bucket_update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id',
		action: 'bucket.update',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: UpdateBucketBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Change a bucket's name, roles, managers, or its registration and verification settings. Editing the bucket entity needs manager access to the bucket itself, not merely to a project it backs."
	},

	/* ----------------------------------------------- writes: end-users (4) */
	{
		tool: 'bucket_user_create',
		method: 'POST',
		path: '/admin/api/buckets/:id/users',
		action: 'enduser.create',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: CreateEndUserBody,
		querySchema: null,
		pathParams: ['id'],
		summary: 'Create an end-user account in a bucket.'
	},
	{
		tool: 'bucket_user_update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id/users/:uid',
		action: 'enduser.update',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: UpdateEndUserBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Change an end-user's email, roles, active state, or claims. Deactivating is a sign-in decision, not a deletion."
	},
	{
		tool: 'bucket_user_password_reset',
		method: 'POST',
		path: '/admin/api/buckets/:id/users/:uid/password',
		action: 'enduser.password.reset',
		consequence: 'high',
		requiredRole: null,
		bodySchema: ResetPasswordBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Replace an end-user's password. The previous one is unrecoverable and the account holder is not asked."
	},
	{
		tool: 'bucket_user_delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/users/:uid',
		action: 'enduser.delete',
		consequence: 'high',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'Permanently delete an end-user account and everything issued to it. Irreversible.'
	},

	/* ---------------------------------------------- writes: federation (4) */
	{
		tool: 'federation_provider_create',
		method: 'POST',
		path: '/admin/api/buckets/:id/federation',
		action: 'federation.provider.create',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: CreateProviderBody,
		querySchema: null,
		pathParams: ['id'],
		// The body carries the provider's own `id`, so the bucket needs a different argument name.
		pathArgs: { id: 'bucketId' },
		summary:
			'Configure an upstream identity provider on a bucket. Available whether or not federation is switched on, so a provider can be prepared first.'
	},
	{
		tool: 'federation_provider_update',
		method: 'PATCH',
		path: '/admin/api/buckets/:id/federation/:providerId',
		action: 'federation.provider.update',
		consequence: 'ordinary',
		requiredRole: null,
		bodySchema: UpdateProviderBody,
		querySchema: null,
		pathParams: ['id', 'providerId'],
		summary:
			"Change an upstream provider's configuration, or enable/disable it."
	},
	{
		tool: 'federation_provider_delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/federation/:providerId',
		action: 'federation.provider.delete',
		consequence: 'high',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'providerId'],
		summary:
			'Remove an upstream identity provider from a bucket. Deliberately available even with federation switched off, so a deployment can delete a provider it no longer trusts. Users who signed in only through it lose that route in.'
	},
	{
		tool: 'federation_identity_delete',
		method: 'DELETE',
		path: '/admin/api/buckets/:id/users/:uid/identities/:providerId',
		action: 'federation.identity.delete',
		consequence: 'high',
		requiredRole: null,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid', 'providerId'],
		summary:
			"Sever one end-user's link to one upstream provider. The account survives; only the link is removed."
	},

	/* ---------------------------------------------------- writes: keys (2) */
	{
		tool: 'jwks_generate',
		method: 'POST',
		path: '/admin/api/jwks',
		action: 'jwks.generate',
		consequence: 'high',
		requiredRole: 'super_admin',
		bodySchema: GenerateKeyBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Generate a new RSA signing key. Takes effect for signing only after a restart; the key is published immediately so verifiers can pick it up first.'
	},
	{
		tool: 'jwks_delete',
		method: 'DELETE',
		path: '/admin/api/jwks/:kid',
		action: 'jwks.delete',
		consequence: 'high',
		requiredRole: 'super_admin',
		bodySchema: null,
		querySchema: null,
		pathParams: ['kid'],
		summary:
			'Delete a signing key. Refused if it would leave no signing key. Tokens already signed with it stop verifying once it is gone.'
	},

	/* ------------------------------------------------ writes: settings (2) */
	{
		tool: 'settings_update',
		method: 'PUT',
		path: '/admin/api/settings',
		action: 'settings.update',
		consequence: 'high',
		requiredRole: 'super_admin',
		bodySchema: UpdateSettingsBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Change server settings. The merged configuration is validated first, so a combination the server would refuse at boot is refused here instead of taking the instance down on restart. Most changes apply only after a restart, and the result says so.'
	},
	{
		tool: 'smtp_settings_update',
		method: 'PUT',
		path: '/admin/api/settings/smtp',
		action: 'smtp.settings.update',
		consequence: 'high',
		requiredRole: 'super_admin',
		bodySchema: UpdateSmtpBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Change the outbound mail settings. The password is write-only: it can be set but never read back.'
	}
] as const satisfies readonly McpTool[];

export const mcpCatalogue: readonly McpTool[] = catalogue;

export type McpToolName = (typeof catalogue)[number]['tool'];

/*
 * Console operations deliberately absent from the catalogue, each with the reason it is withheld —
 * read by the drift guard's failure message and by the refusal an agent receives, so the message and
 * this table cannot disagree.
 *
 * Enumerated rather than defaulted: a fifth exclusion must be a reviewable edit that fails the suite
 * until the specification is updated, never something that happens by omission.
 */
export interface ExcludedConsoleOperation {
	readonly method: AuditedMethod | 'GET';
	readonly path: string;
	readonly reason: string;
}

export const excludedConsoleOperations: readonly ExcludedConsoleOperation[] = [
	{
		method: 'POST',
		path: '/admin/api/setup',
		reason:
			'First-run setup runs when no administrator exists yet, so there is nobody who could authorize an agent to perform it. Console-only.'
	},
	{
		method: 'POST',
		path: '/admin/api/logout',
		reason:
			'Ends a browser session, which an agent connection does not have. Session lifecycle, not a change to a managed entity.'
	},
	{
		method: 'DELETE',
		path: '/admin/api/projects/:id',
		reason:
			'Deleting a project destroys a container of clients with nothing left afterwards to inspect or restore. Withheld from agents by operator decision — delete it in the admin console instead.'
	},
	{
		method: 'DELETE',
		path: '/admin/api/buckets/:id',
		reason:
			'Deleting a user bucket destroys a container of end-user accounts with nothing left afterwards to inspect or restore. Withheld from agents by operator decision — delete it in the admin console instead.'
	}
];

const byTool = new Map<string, McpTool>(catalogue.map((e) => [e.tool, e]));

export function toolByName(name: string): McpTool | undefined {
	return byTool.get(name);
}

export function excludedOperationFor(
	name: string
): ExcludedConsoleOperation | undefined {
	/*
	 * Maps the tool name an agent would plausibly guess for a withheld operation onto the exclusion, so
	 * the refusal can say *why* and name the console rather than answering a bare "no such tool".
	 */
	const guesses: Record<string, string> = {
		project_delete: '/admin/api/projects/:id',
		bucket_delete: '/admin/api/buckets/:id',
		setup_bootstrap: '/admin/api/setup',
		logout: '/admin/api/logout'
	};
	const path = guesses[name];
	return path
		? excludedConsoleOperations.find((e) => e.path === path)
		: undefined;
}
