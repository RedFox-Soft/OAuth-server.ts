import type { TSchema } from 'elysia';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';

import {
	type AuditAction,
	type AuditedMethod
} from '../consts/admin_audit_routes.js';
import { CreateClientBody, UpdateClientBody } from '../admin/clients/schema.js';
import {
	CreateResourceBody,
	UpdateResourceBody
} from '../admin/resources/schema.js';
import { CreateAdminBody, UpdateAdminBody } from '../admin/users/schema.js';
import {
	ChangeBucketAddressBody,
	CreateBucketBody,
	MoveBucketOwnerBody,
	UpdateBucketBody
} from '../admin/buckets/schema.js';
import {
	BulkUsersBody,
	ChangeEndUserEmailBody,
	CreateEndUserBody,
	UpdateEndUserBody,
	ResetPasswordBody,
	LockEndUserBody,
	UserListQuery
} from '../admin/users-end/schema.js';
import {
	CreateProviderBody,
	MoveProviderBody,
	UpdateProviderBody
} from '../admin/federation/schema.js';
import { PublishedSettingsBody } from '../admin/settings/schema.js';
import { UpdateSmtpBody } from '../admin/settings/smtp/schema.js';
import {
	CreatePlanBody,
	SetProjectPlanBody,
	UpdatePlanBody
} from '../admin/plans/schema.js';
import { UpdateSentryBody } from '../admin/settings/sentry/schema.js';
import {
	GenerateKeyBody,
	RetireKeyBody,
	RevokeKeyBody,
	RotateKeyBody
} from '../admin/jwks/schema.js';
import { GenerateBucketKeyBody } from '../admin/bucket_keys/schema.js';
import { AuditQuery } from '../admin/audit/schema.js';
import {
	AddBucketGroupMembersBody,
	AssignBucketGroupConnectionBody,
	BucketGroupMemberPageQuery,
	CreateBucketGroupBody,
	RenameBucketGroupBody
} from '../admin/bucket-groups/schema.js';
import {
	CreateGroupBody,
	UpdateGroupBody,
	AddMemberBody,
	UpdateMemberBody,
	CreateInvitationBody
} from '../admin/groups/schema.js';
import { ErrorQuery, ErrorSummaryQuery } from '../admin/errors/schema.js';
import {
	ActivityOverviewQuery,
	BucketActivityQuery
} from '../admin/activity/schema.js';
import {
	AssignConnectionBody,
	CreateConnectionBody,
	IssueCredentialBody,
	UpdateConnectionBody
} from '../admin/provisioning/schema.js';

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
 * `settings_update` is the single exception, and it is one because its route validates against
 * nothing: `UpdateSettingsBody` is an open map, and every rule about a setting lives in the handler,
 * which reads SETTINGS_CATALOG. `PublishedSettingsBody` is derived from that same catalog, so the rule
 * above still holds where it matters — the published schema and the enforced one have one source — and
 * the schema module's own comment carries the argument.
 *
 * Paths are written in Elysia's declaration form so they compare directly against `elysia.routes`.
 * Matching is exact on (method, path), never a prefix test: `POST /admin/api/projects` and
 * `POST /admin/api/projects/:id/users` are different operations on different entities.
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
	 * handler's own `assertSuperAdmin`, which the tool reaches by re-dispatch. Present so a description can
	 * tell an agent what it needs, and so a drift test can compare it against the handler.
	 *
	 * `false` covers two different things on purpose: a route open to any authenticated administrator,
	 * and a route that is scope-filtered rather than privilege-gated (`project_list` returns the projects the
	 * caller manages). Neither refuses a non-super administrator outright.
	 */
	readonly superAdminOnly: boolean;
	readonly bodySchema: TSchema | null;
	readonly querySchema: TSchema | null;
	readonly pathParams: readonly string[];
	/*
	 * Argument name to use for a path parameter whose declaration name collides with a body field.
	 *
	 * A tool takes one flat argument object, so `:id` and a body property called `id` cannot both be
	 * `id` — one silently wins and the other is dropped. That is not hypothetical: the federation
	 * provider create route is `/admin/api/projects/:id/federation` while its body carries the
	 * provider's own `id`, so the provider id vanished and every call failed validation until this
	 * existed. `test/mcp/catalogue_drift.spec.ts` now refuses any tool whose final argument names
	 * collide, so the next such route fails the suite instead of shipping broken.
	 */
	readonly pathArgs?: Readonly<Record<string, string>>;
	/*
	 * High-consequence for one target only: the call is gated as `high` when the named path parameter (by its
	 * declared name, `id`, not its argument alias) equals the value. The provider writes use it for the
	 * administrators' project (specs/080): there they decide who can sign in to the console, while on an
	 * ordinary project one confirmation more would buy nothing. Data rather than a predicate, so the catalogue
	 * still exports as JSON for the documentation. The token already binds the target, so a confirmation for
	 * one project cannot be spent on another.
	 */
	readonly highWhen?: { readonly pathParam: string; readonly equals: string };
	readonly summary: string;
}

/* The call's path values, keyed by the route's declared parameter names. */
export function pathValues(
	tool: McpTool,
	args: Record<string, unknown>
): Record<string, string> {
	return Object.fromEntries(
		tool.pathParams.map((name) => [name, String(args[pathArgName(tool, name)])])
	);
}

/* Whether this call is gated: always for a `high` tool, and for its targets for one with `highWhen`. */
export function isHighCall(
	tool: McpTool,
	args: Record<string, unknown>
): boolean {
	return (
		tool.consequence === 'high' ||
		(tool.highWhen !== undefined &&
			pathValues(tool, args)[tool.highWhen.pathParam] === tool.highWhen.equals)
	);
}

/* Whether some call of this tool can be gated, so its schema must offer the confirmation. */
export function mayBeHigh(tool: McpTool): boolean {
	return tool.consequence === 'high' || tool.highWhen !== undefined;
}

const onConsoleBucket = { pathParam: 'id', equals: ADMIN_BUCKET_ID } as const;

/* The argument name a path parameter is addressed by, after any alias. */
export function pathArgName(tool: McpTool, param: string): string {
	return tool.pathArgs?.[param] ?? param;
}

const catalogue = [
	/* ---------------------------------------------------------------- reads (17) */
	{
		tool: 'whoami',
		method: 'GET',
		path: '/admin/api/me',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The administrator this agent is acting as: their id, email, whether they are a super administrator, and the teams they belong to. `can` states what they may create — `createProject`, `addressForms` (the address forms they may give a project: `path`, `subdomain` and, for a super administrator, `host`; the first is the one to offer by default), `createTeam` — and `instance`, whether the instance-wide operations are theirs. While plans are enforced it also states what the plan still allows them: `nameSlug` (false when a new project is given a generated address name, so `slug` must be left out of project_create), `projects` and `teams` (`count` against `max`; null when unlimited).'
	},
	{
		tool: 'resource_list',
		method: 'GET',
		path: '/admin/api/projects/:id/resources',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Every protected resource (API) declared in a project, sorted by identifier: the audiences this server mints tokens for on that project's behalf, with the scopes each recognises, how its tokens are verified, and their lifetime. `namespace` is `project` for a project with an address of its own — whose identifiers are unique to it — and `root` for one served at the root, which shares its namespace with the other root-served projects; only this project's declarations are listed either way."
	},
	{
		tool: 'resource_get',
		method: 'GET',
		path: '/admin/api/projects/:id/resources/:resourceId',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'resourceId'],
		summary:
			'One declared protected resource. The resourceId is the canonical resource identifier itself, percent-encoded into the path, and names the declaration in this project: another tenant may declare the same identifier in its own.'
	},
	{
		tool: 'resource_vouching_check',
		method: 'GET',
		path: '/admin/api/projects/:id/resources/:resourceId/vouching',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'resourceId'],
		summary:
			"Whether a declared resource's own protected resource metadata currently vouches for it — describes this identifier and lists the issuer its tokens carry — found by the MCP discovery order (a 401 challenge's resource_metadata, then the path-inserted, then the root well-known). A diagnostic: it blocks nothing, and returns only a status, the step that answered, a reason, and the expected issuer."
	},
	{
		tool: 'client_list',
		method: 'GET',
		path: '/admin/api/projects/:id/clients',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"The OAuth clients (applications) of a project: those an administrator created and those that registered themselves at the project's own address (`registeredDynamically: true` — listed and readable, but changed only through their registration access token). Each carries its `corsOrigins`. Never returns a client secret."
	},
	{
		tool: 'client_get',
		method: 'GET',
		path: '/admin/api/projects/:id/clients/:clientId',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
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
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The administrator accounts of this instance, each marked when it is a super administrator.'
	},
	{
		tool: 'admin_sign_in_readiness_get',
		method: 'GET',
		path: '/admin/api/admins/sign-in-readiness',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'What turning password sign-in to the console off would do: whether it is on, how many super administrators could still sign in through an identity provider of the Administrators project, and which administrators could not. Turning it off is refused to an agent: only a console session that signed in through such a provider may.'
	},
	{
		tool: 'team_list',
		method: 'GET',
		path: '/admin/api/teams',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The teams this administrator belongs to (every team, for a super administrator). A team owns projects — and through them their applications and APIs — and belonging to it is what grants access to them; each row counts what it owns as `owns.projects`.'
	},
	{
		tool: 'team_get',
		method: 'GET',
		path: '/admin/api/teams/:id',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'One team: its name, kind, and the administrators in it — each with `role`, `email` and `active` (false for a deactivated account), owners first. `owns` names the projects it owns, which are what keep it from being deleted. `can` states what the server will accept from the caller on it: `manageMembers` (team_member_update, team_member_remove), `invite` (team_invite, team_invitation_revoke), `addExisting` (team_member_add — a super administrator only; anyone else adds people with team_invite), `rename` (team_update) and `delete`; a personal team can be renamed and nothing else, and the System team nothing. Readable by its members and super administrators.'
	},
	{
		tool: 'team_invitation_list',
		method: 'GET',
		path: '/admin/api/teams/:id/invitations',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Pending invitations into a team. Never returns an invitation token — a token exists only in the mail it was sent in.'
	},
	{
		tool: 'scope_get',
		method: 'GET',
		path: '/admin/api/scope',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			"The console's active team and the teams available to switch to. An agent has no console session: name a team per call instead of switching."
	},
	{
		tool: 'project_list',
		method: 'GET',
		path: '/admin/api/projects',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The projects: every one for a super-administrator, otherwise those the caller manages. For a super-administrator the list includes the administrators\' own project, marked `reserved: "administrators"`; nobody else sees it. Each row carries `can` and `blockers`, as project_get does, and `addressForm` (root, path, subdomain, host or unaddressed), `issuer` (null when unaddressed), `hostReached` (a request has arrived at its subdomain or hostname; false for a project at a path) and `held` (a provisioning connection of the project is holding a deprovisioning). A project scheduled for deletion is still listed, with `deletion` as project_get describes it.'
	},
	{
		tool: 'project_get',
		method: 'GET',
		path: '/admin/api/projects/:id',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"One project: its name, owning team, and registration and verification settings. Its groups of end users are read with project_group_list. A super-administrator may read the administrators' own project here (`reserved: \"administrators\"`); its accounts are read with admin_list, not through the project. `can` states which operations the server will accept from the caller on it: `manageUsers` (project_user_*, the identity tools, project_group_member_add/remove, and reading providers, provisioning and groups), `edit` (federation_provider_create/update/delete, provisioning_connection_create/update/delete/release, provisioning_credential_*, project_group_create/update/delete/assign_connection, project_user_assign_connection, project_key_*), `editSettings` (project_update), `readActivity` (project_activity_get), `changeAddress` (project_address_change), `move` (project_owner_change) and `delete`; a false flag is a refusal, so do not try it. `changeAddress` and `delete` also depend on the project's state for some callers: an owner of its team may change a path or subdomain address only while no application, identity provider or provisioning connection depends on it, and a member who is not an owner may delete it only while it holds no accounts. `blockers` is the state behind them: `addressable` is false for a project that signs with the instance keys, `dependents` counts the applications, providers and connections depending on it and `accounts` the accounts it holds — each null when it could not change the caller's answer and so was not read. `addressForm` is root, path, subdomain, host or unaddressed; `issuer` and `discoveryUrl` are what a client is configured with (null when unaddressed); `applications` and `apis` count what it holds (client_list, resource_list). `edit` also governs its applications and APIs (client_create/update/delete, client_secret_rotate, resource_declare/update/delete). Its counts are read with project_summary_get. A project scheduled for deletion carries `deletion` — `scheduledAt`, `purgeAt` (the date it will be destroyed) and `scheduledBy` — and answers nobody at its address until then: every change to it or to anything it holds is refused with 409 until project_restore brings it back, while reading keeps working. Deleting a project stays console-only for agents even where `can.delete` is true."
	},
	{
		tool: 'project_summary_get',
		method: 'GET',
		path: '/admin/api/projects/:id/summary',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Count what a project holds, computed when asked: its accounts (`users`), how many are unverified, without an authenticator and without any linked upstream identity; its groups of end users (`groups`); its provisioning connections and how many are holding a deprovisioning (`held`); its identity providers (`providers.enabled`, and `providers.creating` — enabled ones that create accounts on first sign-in); whether mail delivery is configured; and whether federation is switched on for the instance (`federationEnabled` — when false no project's sign-in page shows a provider button). `withoutEnabledLink` counts accounts with no link to an enabled identity provider (who could not sign in were passwords turned off) and `passwordWithoutAuthenticator` accounts with no authenticator whose password is not known to be absent (who an authenticator requirement would ask to enrol); `applications` and `apis` count the applications and declared APIs it holds; on the default project a sign-in change's preview also counts the applications signing in there. `activeThisMonth` is present only to a caller with `can.readActivity`, and absent rather than zero before counting began. Counts only, never who. `plan`, while plans are enforced (to a super administrator always), is the project's plan: its `limits`, `features`, `usage`, `warnings` (`near` at 80% of a limit, `reached` at 100%) and `signUpsPaused` (new self-service accounts paused at the monthly-active-user cap; sign-ins never are); null for a System project, which has none. Readable by anyone who may read the project (project_get's `can.read`)."
	},
	{
		tool: 'project_activity_get',
		method: 'GET',
		path: '/admin/api/projects/:id/activity',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: BucketActivityQuery,
		pathParams: ['id'],
		summary:
			"Read a project's monthly active users: this month so far, each day of the month and the previous 12 months, in total and by kind of activity (local sign-in, upstream sign-in, renewal) and directory-provisioned accounts. A super administrator may also read the reserved projects, by id; a deleted project can be read by id by a super administrator and by members of the team that owned it last, and is refused to anyone else exactly as an unknown id is. The answer names the project (`name`) and, for a deleted one, `deletedAt` and the team that last owned it (`lastOwner`, null when not recorded). Counts only, never who."
	},
	{
		tool: 'activity_overview',
		method: 'GET',
		path: '/admin/api/activity',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: ActivityOverviewQuery,
		pathParams: [],
		summary:
			"List every project on the instance with its monthly active users, including the default and administrators projects and deleted projects, each with its customer (the team that owns it, or owned it when it was deleted) and its last 13 months and the month's days. Also answers each customer's summed figures and contacts (its owners' emails), the instance's totals, and the projects whose figure rose or fell sharply between the last two closed months. A customer's figure is a sum of its projects', not a count of distinct people. Counts only, never which end users. A super administrator reads the whole instance; any other administrator reads only the projects owned by teams they belong to and the deleted projects those teams owned last, with those teams as the customers and every total computed over those projects alone — the reserved projects are never included for them."
	},
	{
		tool: 'project_user_list',
		method: 'GET',
		path: '/admin/api/projects/:id/users',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: UserListQuery,
		pathParams: ['id'],
		summary:
			"A page of the end-user accounts held in one project, ordered by email, as `{ users, totalResults }`. `q` finds people whose email or username starts with it, in any letter case, or whose id is exactly it. Narrow with `status` (active, deactivated, locked), `managedBy` (`console` for people administrators manage, or a provisioning connection's id), `verified` and `authenticator` (yes or no). Page with `startIndex` (1-based) and `count` (1–200, default 50). Each user carries their groups; `passwordSet` says whether a password anyone chose opens the account, when known. Read one person in full with project_user_get."
	},
	{
		tool: 'project_user_get',
		method: 'GET',
		path: '/admin/api/projects/:id/users/:uid',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"One end-user of a project, as a row of project_user_list, and — when they are locked — who locked them: `lockedLocally.byEmail` is that administrator's email, or null when their account no longer exists."
	},
	{
		tool: 'project_user_session_list',
		method: 'GET',
		path: '/admin/api/projects/:id/users/:uid/sessions',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'The applications an end-user is signed in to in this project, as `{ applications }`: per application its `clientId` and `clientName`, `signedInAt`, `lastTokenAt` (when this server last issued it a token for the person — not when the application used one) and `offline` (it holds offline access no live session carries). A row with `clientId: null` is a sign-in that has reached no application yet. No network address, browser or device is stored, so none is returned. Sign the person out of one application with project_user_application_sign_out.'
	},
	{
		tool: 'federation_provider_list',
		method: 'GET',
		path: '/admin/api/projects/:id/federation',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'The upstream identity providers configured on a project. Never returns a provider client secret.'
	},
	{
		tool: 'federation_provider_get',
		method: 'GET',
		path: '/admin/api/projects/:id/federation/:providerId',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'providerId'],
		summary:
			"One upstream identity provider of a project, with what it takes to run it: `callbackUri` (the redirect URI to register at the provider) and `callbackStability` (`provisional` while the project's address may still change), `recognised` (the catalogue entry it matches, or null), `logoutSignals` (whether the provider can send Global Token Revocation and back-channel logout at all — never for GitHub), `capabilities` (whether this instance accepts each), `boundConnection` (the SCIM provisioning connection bound to it, or null), `linkedUsers` (how many of the project's users are linked to it — the people a disable or delete affects), `recommendedCorrelation` (the claim and SCIM attribute a provisioning connection should match on) and `warnings`. Never returns its client secret."
	},
	{
		tool: 'project_group_list',
		method: 'GET',
		path: '/admin/api/projects/:id/groups',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"A project's groups of end users, each with its member count and, for one a SCIM directory manages, the connection that owns it. Group names are what relying parties see in the `groups` claim."
	},
	{
		tool: 'project_group_get',
		method: 'GET',
		path: '/admin/api/projects/:id/groups/:gid',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'gid'],
		summary:
			"One group of the project's end users: its name, external id and owning connection if a directory manages it, and its member count."
	},
	{
		tool: 'project_group_member_list',
		method: 'GET',
		path: '/admin/api/projects/:id/groups/:gid/members',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: BucketGroupMemberPageQuery,
		pathParams: ['id', 'gid'],
		summary:
			"A page of a group's members (id, email, userName), up to 1,000 at a time, with the total. `q` narrows it to members whose email or username starts with it, in any letter case, or whose id is exactly it; the total is then the matching members'."
	},
	{
		tool: 'provisioning_connection_list',
		method: 'GET',
		path: '/admin/api/projects/:id/provisioning-connections',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'The SCIM provisioning connections of a project, each with its SCIM base URL, token endpoint, client id, managed-user count and warnings. Never returns a secret or a static token.'
	},
	{
		tool: 'provisioning_connection_get',
		method: 'GET',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'connectionId'],
		summary:
			'One SCIM provisioning connection: everything a directory administrator needs to configure it, which credentials it holds, which kinds of credential this instance would issue it now (`availableCredentialKinds`), and how many users and groups it manages. Never returns a secret or a static token.'
	},
	{
		tool: 'provisioning_hold_get',
		method: 'GET',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId/hold',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'connectionId'],
		summary:
			"Whom a SCIM provisioning connection held by its mass-deprovisioning guard has been refused the deactivation or deletion of: `{held: false}`, or `{held: true, since, count, refused, total}` where each refused row names the user (`userId`, `email`, `userName`), the last refused `operation`, `firstAt`, `lastAt` and `attempts`, most recent first, at most 1,000 rows. Releasing the hold (provisioning_connection_release) lets the directory's retries of exactly these go through — read this first."
	},
	{
		tool: 'provisioning_hold_list',
		method: 'GET',
		path: '/admin/api/provisioning-holds',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'Every SCIM provisioning connection held by its mass-deprovisioning guard, across the projects project_list shows the caller: `{count, connections}`, each with `projectId`, `projectName`, `connectionId`, `displayName`, `since` (when the hold began) and `refused` (how many removals it has refused so far), oldest hold first. While a connection is held, the people the directory removes keep their access; read provisioning_hold_get before releasing one.'
	},
	{
		/*
		 * Published for the reason federation_catalogue_list is: the field names and pitfalls of Entra and Okta
		 * are facts an agent cannot derive, and without them it would configure a directory wrongly.
		 */
		tool: 'provisioning_directory_list',
		method: 'GET',
		path: '/admin/api/projects/:id/provisioning-connections/directories',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"How to connect each known directory to a project over SCIM, in the directory's own words: `directories`, one each for `entra` (Microsoft Entra ID), `okta` and `generic`, with `displayName`, `recommendedCredential` and `fallbackCredential` (the kind to pass to provisioning_credential_issue), `recommendedCorrelation`, `labels` (the directory's names for the SCIM base URL, token endpoint, client id, client secret and static token), the ordered `steps`, known `pitfalls`, and `values` — this project's SCIM base URL and token endpoint, null when it has no SCIM address. Set a connection's `directory` to the matching id. Returns no credential."
	},
	{
		/*
		 * Published rather than withheld because the callback address is the one thing an agent cannot
		 * derive: it depends on whether the project is served at the root and on the slug an operator chose.
		 * Without it an agent could still configure a provider — one that cannot work, failing later on the
		 * upstream's page with nothing on this server to explain it.
		 */
		tool: 'federation_catalogue_list',
		method: 'GET',
		path: '/admin/api/projects/:id/federation/catalogue',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'What it takes to connect a recognised identity provider to a project: the ordered steps, where to perform them, and the exact callback address to register with the upstream. Returns no configured provider and no credential. Connect one by passing that provider catalogueId to federation_provider_create with the client id and secret it issued.'
	},
	{
		tool: 'federation_identity_list',
		method: 'GET',
		path: '/admin/api/projects/:id/users/:uid/identities',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
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
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The editable server settings, with the catalogue describing each one and its current value.'
	},
	{
		tool: 'plan_list',
		method: 'GET',
		path: '/admin/api/plans',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The plan catalogue: each plan’s limits (monthly active users per project, projects per administrator, applications and APIs per project; null is unlimited), its features (enterpriseSignIn, customSlug, customDomain), whether it is the default a new project is put on, and how many projects are on it. Plans limit tenants only while the plans.enabled setting is on, and never a super administrator or a System project.'
	},
	{
		tool: 'smtp_settings_get',
		method: 'GET',
		path: '/admin/api/settings/smtp',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The outbound mail settings. The password is never returned, only whether one is set.'
	},
	{
		tool: 'sentry_settings_get',
		method: 'GET',
		path: '/admin/api/settings/sentry',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The Sentry integration settings. The ingestion credential is never returned, only whether one is set.'
	},
	{
		tool: 'jwks_list',
		method: 'GET',
		path: '/admin/api/jwks',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'The instance (root) signing keys, each with its state — published (verifies, may be promoted once promotableAt has passed; signedUntil when it signed before a promotion replaced it), signing (one per algorithm), or retired (still verifies until removableAt, then hidden). Nothing here needs a restart. No key material is returned; the public keys are at the root /jwks.'
	},
	{
		tool: 'project_key_list',
		method: 'GET',
		path: '/admin/api/projects/:id/keys',
		action: null,
		consequence: 'read',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"The signing keys of a project that has an address of its own, each with its state — published (verifies, may be promoted once promotableAt has passed; signedUntil when it signed before a promotion replaced it), signing (one per algorithm), or retired (still verifies until removableAt). No key material is returned; the public keys are at the project's jwks_uri. A project served at the root signs with the instance keys (jwks_list)."
	},
	{
		tool: 'audit_list',
		method: 'GET',
		path: '/admin/api/audit',
		action: null,
		consequence: 'read',
		/*
		 * Scope-filtered rather than role-gated, which is why this is `null` and not `super_admin`. The
		 * route serves everyone: an administrator sees the trail of the teams they belong to, a super
		 * administrator sees the instance. Naming a role here would be a claim the handler does not make.
		 */
		superAdminOnly: false,
		bodySchema: null,
		querySchema: AuditQuery,
		pathParams: [],
		summary:
			'The administrative audit trail for the teams this administrator belongs to, newest first, filterable by actor, action, target, surface and time window. A super administrator sees the whole instance, including actions that belong to no team. Filter `viaSurface=mcp` for actions taken through an agent, `viaSurface=scim` for changes a provisioning connection made and `viaSurface=upstream` for sign-outs an upstream identity provider requested and `viaSurface=self-service` for applications an end user removed from their own connected-apps page. `project=<id>` returns everything that happened to or in one project: its own settings, address, keys and providers, the users, groups, provisioning resources and applications within it (those entries carry `projectId`). `connection=<id>` returns what one provisioning connection did and what administrators did to it. Actions and target types name projects, teams and groups: actions `project.*`, `team.*` and `group.*` (a group of end users), with target types `Project`, `Team` and `Group`; `retiredproject.*` and `RetiredProject` are entries about the former project entity, which no longer exists. `actionPrefix` matches actions starting with the text, such as `project.key.`, and must name whole segments: a prefix that ends partway into a first segment several actions share is refused. Filters only narrow what the caller may already read. Key actions carry the `kid` they acted on. An entry whose actor is a provisioning connection (`connection:<id>`), an upstream identity provider (`upstream:<project>:<provider>`) or an end user (`enduser:<project>:<account>`) carries `actorName`, its name or address now, or null when it no longer exists. An entry means an authorized actor reached the point of applying a change, not that the change took effect.'
	},
	{
		tool: 'error_list',
		method: 'GET',
		path: '/admin/api/errors',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: ErrorQuery,
		pathParams: [],
		summary:
			'Recorded internal server faults, newest first, one entry per distinct fault with an exact occurrence count. Filterable by error code, route, surface, status, client, actor and time window. Only defects are recorded — routine client rejections such as a bad grant or a wrong password never appear. A non-zero `dropped` means recording fell behind and the list is incomplete.'
	},
	{
		tool: 'error_summary',
		method: 'GET',
		path: '/admin/api/errors/summary',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: ErrorSummaryQuery,
		pathParams: [],
		summary:
			'How much is failing over a time window, broken down by error code and by endpoint, most frequent first. Counts sum occurrences rather than distinct faults, so one fault seen 900 times outranks nine seen once. Takes a window only — use error_list to filter by client, actor, status or surface.'
	},
	{
		tool: 'error_purge_preview',
		method: 'GET',
		path: '/admin/api/errors/purge-preview',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: ErrorQuery,
		pathParams: [],
		summary:
			'How many recorded faults, and how many occurrences, a purge with these filters would remove. Reads only — nothing is deleted. Available whether or not this deployment lets an agent perform the purge itself, because reading the consequence of a deletion is not destructive.'
	},
	{
		tool: 'error_by_reference',
		method: 'GET',
		path: '/admin/api/errors/reference/:reference',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['reference'],
		summary:
			'Resolve the reference identifier a caller reported (it looks like err_XXXXXXXXXXXXXXXX) to the one fault it belongs to, and which occurrence it was. Answers not-found rather than an empty result, so a mistyped reference is distinguishable from a record that has aged out.'
	},
	{
		tool: 'error_get',
		method: 'GET',
		path: '/admin/api/errors/:id',
		action: null,
		consequence: 'read',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'One recorded fault with its retained samples: where it arose, how often, when first and last seen. Samples are capped, so a very frequent fault keeps its earliest and its most recent occurrences while the count stays exact. No credential value is ever stored, so none can be read here.'
	},

	/* ---------------------------------------- writes: protected resources (3) */
	{
		tool: 'resource_declare',
		method: 'POST',
		path: '/admin/api/projects/:id/resources',
		action: 'resource.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateResourceBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Declare an MCP server (or any API) as a protected resource of this project, so this server will mint tokens whose audience is exactly that resource. The scope list is the baseline a general-purpose client requests in full, not a catalogue — an omnibus scope is refused. Tokens default to a self-contained JWT the resource verifies against this server\'s published keys, with a fifteen-minute lifetime. Nothing about the resource is fetched: the identifier is unique within the project, so it need not be reachable or deployed yet. `scopeDescriptions` says, per scope, what it lets an app do (`description`, a phrase that follows "The app will be able to") and whether the app only sees something (`kind: "see"`) or acts (`"act"`, the default); the consent page shows these to the person deciding, and a scope without one is shown only by its technical name. A project without an address of its own shares the root namespace, where only a super administrator may declare, amend or remove a resource.'
	},
	{
		tool: 'resource_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/resources/:resourceId',
		action: 'resource.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateResourceBody,
		querySchema: null,
		pathParams: ['id', 'resourceId'],
		summary:
			"Change a declared resource's name, scopes, scope descriptions, token format or lifetime. `scopeDescriptions` replaces the whole map; changing `scopes` without it drops the descriptions of removed scopes. The identifier itself cannot be amended: it is the audience of every token already issued, so replacing it is a delete and a fresh declaration."
	},
	{
		tool: 'resource_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/resources/:resourceId',
		action: 'resource.delete',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'resourceId'],
		summary:
			'Remove a declared protected resource. Token issuance for that audience stops on the next request, so a live integration loses access as its current tokens expire. High-consequence: describe it and confirm before running.'
	},

	/* ------------------------------------------------- writes: clients (4) */
	{
		tool: 'client_create',
		method: 'POST',
		path: '/admin/api/projects/:id/clients',
		action: 'client.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateClientBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Register an OAuth client (application) in a project; it signs that project’s people in for its whole life, and no operation moves it to another. corsOrigins lists the web origins whose browser code may read its responses — an invalid origin refuses the whole list. Only the project’s own client_credentials clients may obtain machine tokens for the APIs declared in it. A confidential client’s generated secret is returned exactly once, here, and is never readable again. partialConsent lets the person untick individual permissions on the consent page — turn it on only for an application that copes with receiving fewer permissions than it asked for. logo takes a data:image/png, image/jpeg or image/webp base64 URL of at most 64 KiB (null removes it), and policyUri and tosUri take https addresses; the consent page shows them only to this organization’s own users, the links only when they are on a redirect URI’s host.'
	},
	{
		tool: 'client_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/clients/:clientId',
		action: 'client.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateClientBody,
		querySchema: null,
		pathParams: ['id', 'clientId'],
		summary:
			"Change a client's registered metadata — redirect URIs, grant types, and the rest. partialConsent lets the person untick individual permissions on the consent page — turn it on only for an application that copes with receiving fewer permissions than it asked for. logo takes a data:image/png, image/jpeg or image/webp base64 URL of at most 64 KiB (null removes it), and policyUri and tosUri take https addresses; the consent page shows them only to this organization’s own users, the links only when they are on a redirect URI’s host."
	},
	{
		tool: 'client_secret_rotate',
		method: 'POST',
		path: '/admin/api/projects/:id/clients/:clientId/secret',
		action: 'client.secret.rotate',
		consequence: 'high',
		superAdminOnly: false,
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
		superAdminOnly: false,
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
		superAdminOnly: true,
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
		/*
		 * High, as admin_deactivate is: `active: false` here is the same act through another door, and
		 * leaving this ordinary let an agent deactivate an administrator without the confirmation the
		 * deactivation tool demands. Reactivating restores access, and a changed address makes the account
		 * unverified — neither is a step an agent should take in one call either.
		 */
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: UpdateAdminBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Activate or deactivate an administrator, or correct their email address. A changed address must be verified again before the administrator can sign in while the administrators' project requires verification, and a super-administrator cannot change their own address while it does. Never grants or withdraws super-administrator status — that is admin_super_grant and admin_super_withdraw."
	},
	{
		tool: 'admin_deactivate',
		method: 'DELETE',
		path: '/admin/api/admins/:id',
		action: 'admin.deactivate',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Deactivate an administrator: the account is kept but can no longer sign in. Refused for the last active super-administrator.'
	},
	{
		tool: 'admin_super_grant',
		method: 'POST',
		path: '/admin/api/admins/:id/super-admin',
		action: 'admin.superadmin.grant',
		/* High: instance-wide authority, over every team, setting and key. */
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Make an administrator a super administrator — a member of Super administrators, with authority over the whole instance. Refused for an inactive administrator.'
	},
	{
		tool: 'admin_super_withdraw',
		method: 'DELETE',
		path: '/admin/api/admins/:id/super-admin',
		action: 'admin.superadmin.withdraw',
		/* High: it can take the authority away from the only people able to restore it. */
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Withdraw super-administrator status from an administrator. Refused for the last active super administrator.'
	},
	{
		tool: 'admin_sign_out',
		method: 'POST',
		path: '/admin/api/admins/:id/sign-out',
		action: 'admin.signout',
		/*
		 * High: it ends a colleague's console sessions, and every token issued to them at the console's
		 * issuer — an agent acting for them included, possibly the one calling.
		 */
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Sign an administrator out everywhere, for a lost or stolen device: every console session they hold ends, and every grant and token issued to them at the console's issuer is revoked, agents' tokens included. The account is untouched and they can sign in again at once. Answers `sessions`, the number of console sessions ended. Refused on your own account (use Log out in the console)."
	},
	{
		tool: 'admin_totp_clear',
		method: 'DELETE',
		path: '/admin/api/admins/:id/totp',
		action: 'admin.totp.clear',
		/*
		 * High, where project_user_totp_clear is ordinary: it removes a second factor from an account that
		 * administers the instance, and signs it out.
		 */
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Reset an administrator's authenticator, for a lost device: the enrolment is cleared along with any failed attempts, and they are signed out everywhere as admin_sign_out does; they set a new one up at their next sign-in. Answers `sessions`. Refused on your own account, and when the administrator has no authenticator."
	},

	/* ------------------------------------------------- writes: teams and projects (12) */
	{
		tool: 'team_create',
		method: 'POST',
		path: '/admin/api/teams',
		action: 'group.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateGroupBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Create a team. The administrator this agent acts for becomes its first owner — a team with no owner would be unreachable the instant it existed.'
	},
	{
		tool: 'team_update',
		method: 'PATCH',
		path: '/admin/api/teams/:id',
		action: 'group.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateGroupBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Rename a team. Requires being an owner of that team, which is a membership kind rather than an instance role.'
	},
	{
		tool: 'team_member_add',
		method: 'POST',
		path: '/admin/api/teams/:id/members',
		action: 'group.member.add',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: AddMemberBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Add an existing administrator to a team as an owner or a plain member. This grants them everything the team owns, in one call, without their agreement — so it is a super administrator’s operation only; anyone else adds people with team_invite, which the person accepts. Refused for a personal team, which cannot be shared.'
	},
	{
		tool: 'team_member_update',
		method: 'PATCH',
		path: '/admin/api/teams/:id/members/:userId',
		action: 'group.member.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateMemberBody,
		querySchema: null,
		pathParams: ['id', 'userId'],
		summary:
			'Promote a member to owner or demote an owner to member. The last owner can be neither demoted nor removed. Owner-only.'
	},
	{
		tool: 'team_member_remove',
		method: 'DELETE',
		path: '/admin/api/teams/:id/members/:userId',
		action: 'group.member.remove',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'userId'],
		summary:
			'Remove an administrator from a team. They lose access to every project, application and end-user the team owns, on their very next request. The last owner cannot be removed. Owner-only.'
	},
	{
		tool: 'team_invite',
		method: 'POST',
		path: '/admin/api/teams/:id/invitations',
		action: 'invitation.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateInvitationBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Invite somebody into a team by email, as an owner or a plain member. Creates an administrator account for them when they accept, if the address has none. Owner-only. Refused for a personal team, which cannot be shared. An owner invitation is judged against the invitee’s plan when it is accepted, not when it is sent. Bounded, to protect the instance’s mail: one invitation per address and team every 10 minutes and at most 5 a day, 100 a day per inviter, and 50 open invitations per team — a refusal carries `retryAfter` in seconds where waiting helps.'
	},
	{
		tool: 'team_invitation_revoke',
		method: 'DELETE',
		path: '/admin/api/teams/:id/invitations/:inviteId',
		action: 'invitation.revoke',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'inviteId'],
		summary: 'Withdraw a pending invitation before it is accepted. Owner-only.'
	},
	{
		tool: 'project_create',
		method: 'POST',
		path: '/admin/api/projects',
		action: 'bucket.create',
		consequence: 'ordinary',
		/* Its route has no privilege gate: any administrator creates into their own scope. */
		superAdminOnly: false,
		bodySchema: CreateBucketBody,
		querySchema: null,
		pathParams: [],
		summary:
			"Create a project. `displayName` is the name its people know the service by, shown at the top of the page where they allow an app access (the consent page); without it that page shows the project's address. A project cannot be created unreachable: at creation it has no providers, so password login cannot be switched off. `totpRequired` makes a password sign-in also require a one-time code from an authenticator app; it governs password sign-in only and never gates a federated one. A `slug` is served as a path beneath this instance, or with `addressForm: 'subdomain'` as a subdomain of its host (`<slug>.<instance host>`); a `host` is a hostname of its own. Each form must be listed in `can.addressForms` from whoami — the operator's `projects.addressForms` setting decides between path and subdomain for a team — and creating at all needs `can.createProject`. While plans are enforced and whoami's `can.nameSlug` is false, leave `slug` out: a random eight-character name is generated in the chosen form, and naming one is refused with `code: 'plan_limit'`; a refusal with that code names the limit and the plan, and only a larger plan, set by a super administrator, lifts it. `teamId` names the team it belongs to — one this administrator is a member of (a super administrator: any team but another administrator's personal team); without it, the administrator's active team."
	},
	{
		tool: 'project_address_change',
		method: 'POST',
		path: '/admin/api/projects/:id/address',
		action: 'bucket.address.change',
		/*
		 * `high`, which puts the two-call confirmation gate in front of it automatically. Moving a project
		 * changes its issuer identifier, so every client integrated with it stops validating tokens on the
		 * next request — a consequence an agent must not be able to cause in one call, and the reason this
		 * is a route of its own rather than a field on `project_update`.
		 */
		consequence: 'high',
		/*
		 * Not instance-only since specs/081: an owner of the project's team may change a path address while
		 * nothing depends on it. Still `high` whoever calls it; the gate binds `expect` through the argument
		 * hash, so a confirmation cannot be spent on a different preview.
		 */
		superAdminOnly: false,
		bodySchema: ChangeBucketAddressBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Move a project to a different address: a path segment (`slug`), a subdomain of this instance (`slug` with `addressForm: 'subdomain'`) or a hostname of its own (`host`), never two. Moving between path and subdomain keeps the slug. Called without `confirm`, it changes nothing and answers with a preview naming what the change reaches — `applications`, `connections`, `providers` (each with the `newCallback` its upstream registration needs) and `resources` — the issuers `from` and `to`, and `expect`, their counts. Called with `confirm: true` and that `expect`, it performs the move: the project's issuer identifier becomes the new address, the previous address stops answering, and everyone signed in signs in again. If what it reaches changed since the preview, it is refused with 409 and the fresh preview. A super administrator may change any project's address; an owner of its team may change a path or subdomain address while no application, identity provider or provisioning connection depends on it, into a form listed in `can.addressForms`; only a super administrator may give it a hostname; a project served at the root cannot be moved at all — project_get states it as `can.changeAddress`, with `blockers.dependents` as the reason."
	},
	{
		tool: 'project_owner_change',
		method: 'PUT',
		path: '/admin/api/projects/:id/owner',
		action: 'bucket.owner.change',
		/*
		 * `high`: it changes who administers a population of people. The team the project leaves loses it
		 * with no step of its own, and nothing restores it but another move by an owner of the team it
		 * joined. The route's own `confirm` stays as well, because the gate's consequence report reads no
		 * entity state and so cannot count what moves with the project.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: MoveBucketOwnerBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Move a project, with its applications and APIs, to another team (`teamId`). Requires owning the team it is in now and belonging to the destination; another administrator's personal team is never a destination. End users, clients and the sign-in address are unaffected. Called without `confirm`, it changes nothing and answers with what would move (`applications`, `apis`); with `confirm: true` it moves it. project_get states the right as `can.move`."
	},
	{
		tool: 'project_restore',
		method: 'POST',
		path: '/admin/api/projects/:id/restore',
		action: 'bucket.restore',
		/*
		 * `high`: it gives a whole population its sign-in back, and every session and token it still holds
		 * becomes valid again — access an administrator switched off on purpose returns in one call otherwise.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Bring back a project that is scheduled for deletion (project_get carries `deletion` with `purgeAt`, the date it will be destroyed): it answers at its address again, exactly as before it was deleted, and every session and token it issued that has not expired is valid again. A provisioning directory that tried to reach it while it was off may need a manual resync. Requires the right to delete it, decided over the accounts it holds now — project_get's `can.delete`. Refused with 409 when the project is not scheduled, or while its destruction is already under way. Deleting a project, and destroying a scheduled one at once, stay in the admin console."
	},
	{
		tool: 'project_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id',
		action: 'bucket.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateBucketBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			"Change a project's name, the name shown to its people (`displayName`; null removes it), or its registration, verification and second-factor settings. Editing the project itself needs membership of the project's team — project_get states it as `can.editSettings`. `totpRequired` governs password sign-in only — it is accepted but inert while `passwordLogin` is off, and it never gates a federated sign-in, so it is not a way to secure a project that signs in through an upstream provider. Requiring verification is refused on every project until mail delivery is configured. A change that tightens who can get in — `passwordLogin` off, `emailVerificationRequired` or `totpRequired` (while passwords are on) turned on, or `registrationOpen` turned on for the default or the administrators' project — changes nothing when called alone: it answers with a preview, `consequences` (one sentence per change, counted), `expect` (the counts) and `changes`; call again with the same settings, `confirm: true` and that `expect` to apply it. If the counts changed since, it is refused with 409 and the fresh preview. Other changes apply at once. A super-administrator configures the administrators' own project here too: opening its registration lets anyone register a console account (the answer carries an advisory while verification is off); requiring verification is also refused until the acting administrator has verified their own address; turning password sign-in off is refused unless the caller's console session signed in through one of its identity providers and a super administrator stays reachable — so an agent, having no console session, is always refused it; with `emailVerificationRequired` off people sign in unverified and applications are told `email_verified: false` until each address is proven; on the administrators' project, sign-up (`registrationOpen`) may be open only while `emailVerificationRequired` is on, so open both in one change and close sign-up before turning verification off. Each refusal names its remedy."
	},

	/* ----------------------------------------------- writes: end-users (10) */
	{
		tool: 'project_user_create',
		method: 'POST',
		path: '/admin/api/projects/:id/users',
		action: 'enduser.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateEndUserBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Create an end-user account in a project. Without `password` no password opens it: the person signs in through an identity provider or sets one through password reset. With `invite: true` (never together with `password`) the person is mailed a link to choose their own password, valid for 7 days; refused before the account is created when the project does not sign people in with a password or mail delivery is not configured, and the answer carries `invitation: sent` or `failed` — a failed send leaves the account, and project_user_invite sends again. Its address starts verified only when the project does not require verification; setting the password through the link verifies it. The person starts with their address unverified in every project, whatever it requires; it becomes verified when they follow a reset or verification link (project_user_verification_send) or an administrator marks it (project_user_mark_verified), and applications are told `email_verified` accordingly.'
	},
	{
		tool: 'project_user_invite',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/invitation',
		action: 'enduser.invitation.send',
		/*
		 * Ordinary: it mails the account's own address, within the cooldown and daily cap a reset shares, and
		 * nothing changes until the mailbox holder chooses a password.
		 */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'Mail an end-user a link to choose their own password, valid for 7 days and once; choosing it also verifies their address. Any earlier reset or invitation link of theirs stops working, and a password they already have keeps working until they choose a new one. The answer never carries the link. Refused for a user a provisioning connection manages, when the project does not sign people in with a password, when mail delivery is not configured, for a user who cannot sign in (deactivated or locked), and when a message was sent too recently (429 with `retryAfter` seconds).'
	},
	{
		tool: 'project_user_mark_verified',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/verified',
		action: 'enduser.verified.mark',
		/* Ordinary: it records what the administrator confirmed, and an address change makes it unverified again. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Mark an end-user's address verified, once it has been confirmed some other way; a verification message still in their inbox stops working. Refused for a user a provisioning connection manages — their address trust is the connection's setting — and, with nothing recorded, for one already verified."
	},
	{
		tool: 'project_user_application_sign_out',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/sessions/:clientId/sign-out',
		action: 'enduser.application.signout',
		/* Ordinary, as signing out everywhere is: the protective act, narrowed to one application. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid', 'clientId'],
		summary:
			"Sign an end-user out of one application: that application is told through back-channel logout, its grants end with every token under them — offline refresh tokens included — and it must ask for consent again. The person's other applications and their sign-in stay as they were. Works on users a provisioning connection manages. 404 when the person is not signed in to that application; read where they are with project_user_session_list."
	},
	{
		tool: 'project_user_email_change',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/email',
		action: 'enduser.email.change',
		/*
		 * High: the address is where password reset and verification mail go, so changing it hands the
		 * account's recovery to whoever holds the new mailbox.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: ChangeEndUserEmailBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Change an end-user's login address. The new address is unverified, and a verification message sent to the old one no longer verifies anything; nothing is mailed by the change — send one with project_user_verification_send. Refused for a user a provisioning connection manages, and for an address another account in the project holds."
	},
	{
		tool: 'project_user_verification_send',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/verification',
		action: 'enduser.verification.send',
		/* Ordinary: it mails the account's own address, within the cooldown and daily cap every door shares. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Mail an end-user a fresh verification message in the project's current method. The answer never carries the link or code. Refused when the address is already verified, when mail delivery is not configured, and when a message was sent too recently."
	},
	{
		tool: 'project_user_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/users/:uid',
		action: 'enduser.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateEndUserBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Change an end-user's active state, claims or profile. `profile` replaces the whole profile of a user administrators manage (refused for one a provisioning connection manages) and reaches tokens as standard claims under the scope the `claims` setting maps them to: `name.givenName` → given_name, `name.familyName` → family_name, `name.middleName` → middle_name, `name.formatted` (else `displayName`) → name, `nickName` → nickname, `locale` → locale (a BCP 47 tag), `timezone` → zoneinfo (a time-zone name such as Europe/Berlin) and the primary of `phoneNumbers` → phone_number (international form, +14155550100); an invalid value is refused with 422 naming `profile.<field>`. Where the profile sets a claim the stored claims also hold, the profile's wins. Their groups are changed with project_group_member_add and project_group_member_remove. Claims replace the account's whole set; sub, email, email_verified and the protocol claims are refused, and a claim is released to a client only once the `claims` setting names it under a scope. Deactivating ends the user's access at once — every session and token, with a logout notice to each relying party registered for one — but keeps the account; reactivating restores sign-in only, never the old tokens or consents."
	},
	{
		tool: 'project_user_totp_clear',
		method: 'DELETE',
		path: '/admin/api/projects/:id/users/:uid/totp',
		action: 'enduser.totp.clear',
		/*
		 * Ordinary rather than gated. The confirmation gate is for what cannot be undone; this is the
		 * undoing — the state it repairs is a person locked out of their own account, and its cost is one
		 * re-enrolment at their next sign-in.
		 */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Clear an end-user's authenticator enrolment. Their existing authenticator stops working at once and their sessions end; they set a new one up at their next sign-in. Use when someone has lost the device holding their codes. Their password, grants and tokens are untouched."
	},
	{
		tool: 'project_user_lock',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/lock',
		action: 'enduser.lock',
		/*
		 * Ordinary, as deactivating through project_user_update is: it is the protective act, and what it costs
		 * the user is signing in and consenting again once it is lifted.
		 */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: LockEndUserBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'Lock an end-user out, at once: every session and token ends and relying parties registered for back-channel logout are told. Works on users a provisioning connection manages, and the connection cannot undo it — only project_user_unlock can. Use when an account is suspected compromised.'
	},
	{
		tool: 'project_user_sign_out',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/sign-out',
		action: 'enduser.signout',
		/* Ordinary, as the lock is: the same protective act, minus the block on signing in again. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'Sign an end-user out everywhere: every session and token ends and relying parties registered for back-channel logout are told, but the account stays active and unlocked, so they can sign in again at once (and consent afresh). Works on users a provisioning connection manages. Use for a lost or stolen device; use project_user_lock when the person must not get back in.'
	},
	{
		tool: 'project_user_unlock',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/unlock',
		action: 'enduser.unlock',
		/* High: it re-admits an account an administrator judged compromised. */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Lift an end-user's lock. Nothing is restored: they sign in afresh, and only if their account is also active."
	},
	{
		tool: 'project_user_password_reset',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/password',
		action: 'enduser.password.reset',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: ResetPasswordBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			"Replace an end-user's password. The previous one is unrecoverable and the account holder is not asked. With `signOut: true` every session and token they hold ends too, and relying parties registered for back-channel logout are told; without it they stay signed in."
	},
	{
		tool: 'project_user_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/users/:uid',
		action: 'enduser.delete',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'Permanently delete an end-user account and everything issued to it; relying parties registered for back-channel logout are told the user signed out. Irreversible.'
	},
	{
		tool: 'project_user_bulk_deactivate',
		method: 'POST',
		path: '/admin/api/projects/:id/users/bulk/deactivate',
		action: 'enduser.bulk.deactivate',
		/* High where the single deactivation is ordinary: one call ends access for up to a hundred people. */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: BulkUsersBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Deactivate up to 100 end-users of a project, named by id, each exactly as project_user_update with `active: false` would: their sessions and tokens end and relying parties are told. Answers `{ results }`, one per id in the order given: `changed`, `skipped` with a `reason` (`provisioned`, `already_inactive`, `not_found`) or `failed` with a `reason`. Each person gets their own audit entry. Repeating the call is harmless.'
	},
	{
		tool: 'project_user_bulk_activate',
		method: 'POST',
		path: '/admin/api/projects/:id/users/bulk/activate',
		action: 'enduser.bulk.activate',
		/* Ordinary, as the single reactivation is; it never lifts a lock. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: BulkUsersBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Reactivate up to 100 end-users of a project, named by id. A locked user stays locked — unlocking is project_user_unlock, one person at a time. Answers `{ results }`, one per id: `changed`, `skipped` with a `reason` (`provisioned`, `already_active`, `not_found`) or `failed`. Each person gets their own audit entry.'
	},
	{
		tool: 'project_user_bulk_sign_out',
		method: 'POST',
		path: '/admin/api/projects/:id/users/bulk/sign-out',
		action: 'enduser.bulk.signout',
		/* Ordinary, as the single sign-out is: the accounts stay active and may sign in again at once. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: BulkUsersBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Sign up to 100 end-users of a project out everywhere, named by id, each as project_user_sign_out would; users a provisioning connection manages included. Answers `{ results }`, one per id: `changed`, `skipped` (`not_found`) or `failed`. Each person gets their own audit entry.'
	},
	{
		tool: 'project_user_bulk_delete',
		method: 'POST',
		path: '/admin/api/projects/:id/users/bulk/delete',
		action: 'enduser.bulk.delete',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: BulkUsersBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Permanently delete up to 100 end-users of a project, named by id, each as project_user_delete would, with everything issued to them. Irreversible. Answers `{ results }`, one per id: `changed`, `skipped` with a `reason` (`provisioned`, `not_found`) or `failed` with a `reason` and, when records survived the sweep, `failedAreas`. Each person gets their own audit entry.'
	},

	/* ---------------------------------------------- writes: federation (5) */
	{
		tool: 'federation_provider_create',
		method: 'POST',
		path: '/admin/api/projects/:id/federation',
		action: 'federation.provider.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateProviderBody,
		querySchema: null,
		pathParams: ['id'],
		// The body carries the provider's own `id`, so the project needs a different argument name.
		pathArgs: { id: 'projectId' },
		highWhen: onConsoleBucket,
		summary:
			'Configure an upstream identity provider on a project. Available whether or not federation is switched on, so a provider can be prepared first. On the Administrators project (`admin`) this decides who can sign in to the console: only a super administrator may, and each such change must be confirmed.'
	},
	{
		tool: 'federation_provider_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/federation/:providerId',
		action: 'federation.provider.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateProviderBody,
		querySchema: null,
		pathParams: ['id', 'providerId'],
		highWhen: onConsoleBucket,
		summary:
			"Change an upstream provider's configuration, or enable/disable it. On the Administrators project (`admin`) this decides who can sign in to the console: only a super administrator may, and each such change must be confirmed."
	},
	{
		tool: 'federation_provider_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/federation/:providerId',
		action: 'federation.provider.delete',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'providerId'],
		summary:
			'Remove an upstream identity provider from a project. Deliberately available even with federation switched off, so a deployment can delete a provider it no longer trusts. Users who signed in only through it lose that route in.'
	},
	{
		tool: 'federation_provider_move',
		method: 'POST',
		path: '/admin/api/projects/:id/federation/:providerId/move',
		action: 'federation.provider.move',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: MoveProviderBody,
		querySchema: null,
		pathParams: ['id', 'providerId'],
		highWhen: onConsoleBucket,
		summary:
			"Move an upstream provider one place `up` or `down` in the order its project's sign-in page shows the buttons — the order federation_provider_list returns. Changes nothing but the order; refused (409) when the provider is already first or last. Answers `{providers}` in the new order. On the Administrators project (`admin`) only a super administrator may, and each move must be confirmed."
	},
	{
		tool: 'federation_identity_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/users/:uid/identities/:providerId',
		action: 'federation.identity.delete',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'uid', 'providerId'],
		summary:
			"Sever one end-user's link to one upstream provider. The account survives; only the link is removed."
	},

	/* ---------------------------------------- writes: SCIM provisioning (8) */
	{
		tool: 'provisioning_connection_create',
		method: 'POST',
		path: '/admin/api/projects/:id/provisioning-connections',
		action: 'provisioning.connection.create',
		/* Ordinary: a connection without a credential can do nothing; issuing one is the gated act. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateConnectionBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Create a SCIM provisioning connection on a project, bound to one of its federation providers. That provider stops creating accounts on first sign-in: from now on the directory creates them. Holds no credential until one is issued. `directory` (entra, okta or generic) chooses whose words the console uses for it; absent, it is inferred from the provider.'
	},
	{
		tool: 'provisioning_connection_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId',
		action: 'provisioning.connection.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: UpdateConnectionBody,
		querySchema: null,
		pathParams: ['id', 'connectionId'],
		summary:
			'Rename, enable or disable a SCIM provisioning connection, change its correlation rule or email trust, or set its mass-deprovisioning guard: threshold {count 1–100000, windowSeconds 300–604800} holds the connection after that many deactivations or deletions within the window; null removes it (refused while held). Disabling refuses every SCIM request through it and leaves its users as they are; no edit releases a hold. `directory` (entra, okta or generic) changes only whose words the console uses for it.'
	},
	{
		tool: 'provisioning_connection_release',
		method: 'POST',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId/release',
		action: 'provisioning.connection.release',
		/*
		 * High: it re-admits what the guard judged a runaway — every deactivation and deletion the directory has
		 * been retrying goes through, and each ends a person's access. Precedent: project_user_unlock.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'connectionId'],
		summary:
			"Release a SCIM provisioning connection held by its mass-deprovisioning guard, and restart its count. The directory's next retries of the deactivations and deletions it was refused go through, ending those users' access — check the directory for the mistake that tripped the guard first. Refused (409) when the connection is not held."
	},
	{
		tool: 'provisioning_connection_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId',
		action: 'provisioning.connection.delete',
		/* High: it ends a customer's provisioning, and its credentials stop working at once. */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'connectionId'],
		summary:
			'Delete a SCIM provisioning connection and revoke every token it obtained. Refused while it still manages any user — disable it instead.'
	},
	{
		tool: 'provisioning_credential_issue',
		method: 'POST',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId/credentials',
		action: 'provisioning.credential.issue',
		/*
		 * High: it hands out the authority to create, change and delete a project's people, and the secret or
		 * static token it returns is shown exactly once.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: IssueCredentialBody,
		querySchema: null,
		pathParams: ['id', 'connectionId'],
		summary:
			'Issue or replace a credential for a SCIM provisioning connection: public keys (signed client assertion), a client secret (Microsoft Entra ID, Okta), or a static token (Okta without OAuth; `lifetimeDays` 90 or 365, default 365). A secret or token is returned exactly once. Replacing a secret with a secret, or a static token with a static token, keeps the current value working until the directory has used the new one and not the old one for an hour, and at most 24 hours (`previousEndsAt` in the answer); pass `overlap: false` to stop it and the tokens it obtained at once — for a leaked value. Keys and a change of kind always replace at once and revoke the old tokens. See provisioning_directory_list for which kind each directory needs.'
	},
	{
		tool: 'provisioning_credential_retire',
		method: 'DELETE',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId/credentials/:kind/previous',
		action: 'provisioning.credential.retire',
		/* Ordinary: it only removes access, like revoke. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'connectionId', 'kind'],
		summary:
			'End a SCIM provisioning connection\'s overlapping previous client secret ("oauth") or static token ("static_token") now, with every token the previous secret obtained; the current value and its tokens keep working. Refused (404) when there is no previous value that still works. Check that the directory uses the new value first — provisioning_connection_get says `stillUsedByDirectory` while it does not.'
	},
	{
		tool: 'provisioning_credential_revoke',
		method: 'DELETE',
		path: '/admin/api/projects/:id/provisioning-connections/:connectionId/credentials/:kind',
		action: 'provisioning.credential.revoke',
		/* Ordinary: it only removes access. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'connectionId', 'kind'],
		summary:
			'Revoke a SCIM provisioning connection\'s OAuth credential ("oauth") or static token ("static_token"), with every token it obtained.'
	},
	{
		tool: 'project_user_assign_connection',
		method: 'POST',
		path: '/admin/api/projects/:id/users/:uid/connection',
		action: 'enduser.connection.assign',
		/*
		 * High: from this moment the user is read-only to every administrator and belongs to an external
		 * directory, which cannot be undone through this surface.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: AssignConnectionBody,
		querySchema: null,
		pathParams: ['id', 'uid'],
		summary:
			'Hand a local end-user to a SCIM provisioning connection, under the userName and/or externalId the directory knows them by, so the directory adopts them instead of creating a duplicate. Afterwards only the directory can change them.'
	},

	/* ------------------------------------------------- writes: groups of end users (6) */
	{
		tool: 'project_group_create',
		method: 'POST',
		path: '/admin/api/projects/:id/groups',
		action: 'bucketgroup.create',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: CreateBucketGroupBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Create a group of end users in a project. The name must be unique in the project in any letter case, and it is the value relying parties receive in the `groups` claim.'
	},
	{
		tool: 'project_group_update',
		method: 'PATCH',
		path: '/admin/api/projects/:id/groups/:gid',
		action: 'bucketgroup.update',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: RenameBucketGroupBody,
		querySchema: null,
		pathParams: ['id', 'gid'],
		summary:
			'Rename a group of end users. Relying parties see the new name in the next token each member receives, so an authorization rule keyed on the old name stops matching. A group a SCIM directory manages is read-only here.'
	},
	{
		tool: 'project_group_delete',
		method: 'DELETE',
		path: '/admin/api/projects/:id/groups/:gid',
		action: 'bucketgroup.delete',
		/* High: every member loses whatever relying parties grant for the group, and nothing restores it. */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'gid'],
		summary:
			'Delete a group of end users and every membership in it. The users themselves are untouched. A group a SCIM directory manages is read-only here.'
	},
	{
		tool: 'project_group_member_add',
		method: 'POST',
		path: '/admin/api/projects/:id/groups/:gid/members',
		action: 'bucketgroup.member.add',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: AddBucketGroupMembersBody,
		querySchema: null,
		pathParams: ['id', 'gid'],
		summary:
			'Add end users of the project to a group, up to 1,000 at a time. Users already in it are left as they are. Provisioned users may be added to a group administrators keep; a group a SCIM directory manages is read-only here.'
	},
	{
		tool: 'project_group_member_remove',
		method: 'DELETE',
		path: '/admin/api/projects/:id/groups/:gid/members/:uid',
		action: 'bucketgroup.member.remove',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'gid', 'uid'],
		summary:
			'Remove one end user from a group. Their sessions and tokens are untouched; the next token they receive no longer names the group.'
	},
	{
		tool: 'project_group_assign_connection',
		method: 'POST',
		path: '/admin/api/projects/:id/groups/:gid/connection',
		action: 'bucketgroup.connection.assign',
		/*
		 * High: from this moment the group belongs to an external directory and is read-only to every
		 * administrator, which cannot be undone through this surface.
		 */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: AssignBucketGroupConnectionBody,
		querySchema: null,
		pathParams: ['id', 'gid'],
		summary:
			'Hand a group administrators keep to a SCIM provisioning connection, so the directory adopts it instead of failing to create one of the same name. Called with only `connectionId`, it changes nothing and answers a conflict carrying the preview: `consequences`, `expect` (`connectionId`, `managed` and `foreign` member counts) and `blockers` (up to 20 members the connection does not manage, by `id` and `email`). Apply it by calling again with `confirm: true` and that `expect`; a stale `expect` is answered with the fresh preview. Refused while any member is someone the connection does not manage. Afterwards only the directory can change it.'
	},

	/* --------------------------------------------------- writes: keys (10) */
	{
		tool: 'jwks_generate',
		method: 'POST',
		path: '/admin/api/jwks',
		action: 'jwks.generate',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: GenerateKeyBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Generate a signing key for the instance key set, in any supported algorithm. The key is published at once and signs only once promoted, which the server allows after the publication window so every instance serves it first. Bounded: at most 12 keys held (signing, published, or retired and still verifying) and 20 made in a day, revoked ones counted; past either the answer is 409 with `reason: "key_limit"`.'
	},
	{
		tool: 'jwks_promote',
		method: 'POST',
		path: '/admin/api/jwks/:kid/promote',
		action: 'jwks.promote',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['kid'],
		summary:
			"Make a published key the one the instance signs with in its algorithm; its algorithm is advertised in discovery at once. The key it replaces returns to published and keeps verifying. Refused before the key's promotableAt. Every root-served client is affected, which is why it is gated."
	},
	{
		tool: 'jwks_retire',
		method: 'DELETE',
		path: '/admin/api/jwks/:kid',
		action: 'jwks.retire',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: RetireKeyBody,
		querySchema: null,
		pathParams: ['kid'],
		summary:
			'Retire a key of the instance key set. The body must name the key again — { "confirm": "<kid>" } — or nothing happens. The key stops signing at once, keeps verifying until removableAt so tokens already issued stay valid, and is then hidden for good. Refused for a key that signs: promote its replacement first.'
	},
	{
		tool: 'jwks_rotate',
		method: 'POST',
		path: '/admin/api/jwks/rotate',
		action: 'jwks.rotate',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: RotateKeyBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Rotate one algorithm of the instance key set in one step. When a published key of that algorithm is past its promotableAt, the oldest such key starts signing (`promoted`), the previous signer returns to published and keeps verifying what it signed (`demoted`), and a new key is generated and published as the next one (`generated`). When no key is ready, only the next key is generated, nothing changes who signs, and `rotatableAt` says from when the algorithm can rotate. Never promotes a key inside its publication window. Every project served at the root signs with these keys, the administrators included, which is why it is gated. Bounded: at most 12 keys held (signing, published, or retired and still verifying) and 20 made in a day, revoked ones counted; past either the answer is 409 with `reason: "key_limit"`.'
	},
	{
		tool: 'jwks_revoke',
		method: 'POST',
		path: '/admin/api/jwks/:kid/revoke',
		action: 'jwks.revoke',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: RevokeKeyBody,
		querySchema: null,
		pathParams: ['kid'],
		summary:
			'Revoke a key of the instance key set that may be compromised. The body must name the key again — { "confirm": "<kid>" } — or nothing happens. Unlike retiring, there is no day of grace: the key leaves the key set at once and every token it signed stops verifying on this instance now and on every other within the key cache bound, for every project served at the root, the console\'s own sign-in included, so people may have to sign in again. When the key is the one signing, the same act puts another key in its place: the oldest published key of its algorithm past its promotableAt, or else a newly generated key that signs at once (`replacementGenerated: true`), in which case relying parties holding a cached key set may reject new tokens until they refresh it. Answers `replacement` with the key now signing. Refused for a key already revoked (409); a hidden or unknown key is 404.'
	},
	{
		tool: 'project_key_generate',
		method: 'POST',
		path: '/admin/api/projects/:id/keys',
		action: 'bucket.key.generate',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: GenerateBucketKeyBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Generate a signing key for a project with an address of its own. The key is published at once and signs only once promoted, which the server allows after the publication window so every instance serves it first. Bounded: at most 12 keys held (signing, published, or retired and still verifying) and 20 made in a day, revoked ones counted; past either the answer is 409 with `reason: "key_limit"`.'
	},
	{
		tool: 'project_key_promote',
		method: 'POST',
		path: '/admin/api/projects/:id/keys/:kid/promote',
		action: 'bucket.key.promote',
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id', 'kid'],
		summary:
			"Make a published key the one the project signs with in its algorithm. The key it replaces in that algorithm keeps verifying. Refused before the key's promotableAt."
	},
	{
		tool: 'project_key_retire',
		method: 'DELETE',
		path: '/admin/api/projects/:id/keys/:kid',
		action: 'bucket.key.retire',
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: RetireKeyBody,
		querySchema: null,
		pathParams: ['id', 'kid'],
		summary:
			'Retire a key the project no longer signs with. The body must name the key again — { "confirm": "<kid>" } — or nothing happens. It stays published until every token it could have signed has expired, then is hidden and tokens signed with it stop verifying. Refused for the signing key. High-consequence: describe it and confirm before running.'
	},
	{
		tool: 'project_key_rotate',
		method: 'POST',
		path: '/admin/api/projects/:id/keys/rotate',
		action: 'bucket.key.rotate',
		/* Ordinary, as promote is: it promotes only a key past its publication window, and the old signer keeps verifying. */
		consequence: 'ordinary',
		superAdminOnly: false,
		bodySchema: RotateKeyBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Rotate one algorithm of a project\'s keys in one step. When a published key of that algorithm is past its promotableAt, the oldest such key starts signing (`promoted`), the previous signer returns to published and keeps verifying what it signed (`demoted`), and a new key is generated and published as the next one (`generated`). When no key is ready, only the next key is generated, nothing changes who signs, and `rotatableAt` says from when the algorithm can rotate. Never promotes a key inside its publication window. Refused for a project served at the root (its keys are the instance\'s) and for an unsupported algorithm. Bounded: at most 12 keys held (signing, published, or retired and still verifying) and 20 made in a day, revoked ones counted; past either the answer is 409 with `reason: "key_limit"`.'
	},
	{
		tool: 'project_key_revoke',
		method: 'POST',
		path: '/admin/api/projects/:id/keys/:kid/revoke',
		action: 'bucket.key.revoke',
		/* Every token the key signed stops verifying at once, and people may have to sign in again. */
		consequence: 'high',
		superAdminOnly: false,
		bodySchema: RevokeKeyBody,
		querySchema: null,
		pathParams: ['id', 'kid'],
		summary:
			'Revoke a key of a project that may be compromised. The body must name the key again — { "confirm": "<kid>" } — or nothing happens. Unlike retiring, there is no day of grace: the key leaves the key set at once and every token it signed stops verifying on this instance now and on every other within the key cache bound, so people may have to sign in again. When the key is the one signing, the same act puts another key in its place: the oldest published key of its algorithm past its promotableAt, or else a newly generated key that signs at once (`replacementGenerated: true`), in which case relying parties holding a cached key set may reject new tokens until they refresh it. Answers `replacement` with the key now signing. Refused for a key already revoked (409); a hidden or unknown key is 404. High-consequence: describe it and confirm before running.'
	},

	/* ------------------------------------------------ writes: settings (3) */
	{
		tool: 'settings_update',
		method: 'PUT',
		path: '/admin/api/settings',
		action: 'settings.update',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: PublishedSettingsBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Change server settings. The merged configuration is validated first, so a combination the server would refuse at boot is refused here instead of taking the instance down on restart. A change takes effect in the instance that serves this call: the result names what it put in force (appliedKeys), what cannot be applied to a running server (pendingRestartKeys), and what is stored but not in force here (notInForceKeys).'
	},
	{
		tool: 'plan_create',
		method: 'POST',
		path: '/admin/api/plans',
		action: 'plan.create',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: CreatePlanBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Add a plan to the catalogue. `default: true` makes it the plan every new project is put on; existing projects keep the plan they record. High-consequence: describe it and confirm before running.'
	},
	{
		tool: 'plan_update',
		method: 'PATCH',
		path: '/admin/api/plans/:id',
		action: 'plan.update',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: UpdatePlanBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Change a plan’s name, a limit or a feature — it applies at once to every project on the plan, and only to what is created next: nothing that exists is removed — or make it the default with `default: true`, which affects only projects created afterwards. High-consequence: describe it and confirm before running.'
	},
	{
		tool: 'plan_delete',
		method: 'DELETE',
		path: '/admin/api/plans/:id',
		action: 'plan.delete',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Remove a plan. Refused for the default plan and for a plan any project is on, with how many. High-consequence: describe it and confirm before running.'
	},
	{
		tool: 'project_plan_set',
		method: 'PUT',
		path: '/admin/api/projects/:id/plan',
		action: 'bucket.plan',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: SetProjectPlanBody,
		querySchema: null,
		pathParams: ['id'],
		summary:
			'Move a tenant’s project to another plan; its team’s next creation is judged by the new plan’s limits. Refused for a System project, which carries no plan. High-consequence: describe it and confirm before running.'
	},
	{
		tool: 'smtp_settings_update',
		method: 'PUT',
		path: '/admin/api/settings/smtp',
		action: 'smtp.settings.update',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: UpdateSmtpBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Change the outbound mail settings. The password is write-only: it can be set but never read back.'
	},
	{
		tool: 'smtp_settings_test',
		method: 'POST',
		path: '/admin/api/settings/smtp/test',
		action: 'smtp.settings.test',
		consequence: 'ordinary',
		superAdminOnly: true,
		bodySchema: null,
		querySchema: null,
		pathParams: [],
		summary:
			'Send a test message through the stored mail settings to the address of the administrator who authorized this connection, never anyone else. Answers with that address when the mail server accepted it; when it refused, the error carries the server’s own reply (for example "535 Authentication failed" or a rejected sender), which is what to fix in smtp_settings_update. Accepted does not mean delivered: ask the administrator whether it arrived, and whether in spam.'
	},
	{
		tool: 'sentry_settings_update',
		method: 'PUT',
		path: '/admin/api/settings/sentry',
		action: 'sentry.settings.update',
		consequence: 'high',
		superAdminOnly: true,
		bodySchema: UpdateSentryBody,
		querySchema: null,
		pathParams: [],
		summary:
			'Change where recorded faults are reported. The ingestion credential is write-only: it can be set but never read back, and sending the mask keeps the stored one. Enabling this requires the error store, because the outbound event is built from the internal record. Both settings take effect in the instance that serves this call; the result reports anything stored but not in force here.'
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
	/*
	 * Why the operation is absent, and the two are not interchangeable.
	 *
	 * `inapplicable` operations have no meaning for an agent — there is no browser session to end, and
	 * nobody to authorize first-run setup. An agent has nothing to be told about them.
	 *
	 * `withheld` operations are ones an agent could perform and an operator has decided it may not. The
	 * server's instructions announce exactly these, so the agent can say where to do them instead rather
	 * than discovering the absence by guessing a tool name. Deriving that list from this field is what
	 * makes a fifth entry reach the instructions by adding it here, and nowhere else.
	 */
	readonly absence: 'withheld' | 'inapplicable';
}

export const excludedConsoleOperations: readonly ExcludedConsoleOperation[] = [
	/*
	 * The administrative client permission list, withheld in full.
	 *
	 * An agent granting another agent — or itself, on a second connection — access to this plane is a
	 * privilege-escalation path, and it is one no operator gains anything from automating: the whole
	 * value of the list is that a human decided which identities may administer the instance. The read
	 * is withheld with the writes, because a published list of permitted identities tells an agent
	 * exactly which identity to impersonate.
	 *
	 * Same reasoning that already withholds purging the error store.
	 */
	{
		method: 'GET',
		path: '/admin/api/mcp/clients',
		absence: 'withheld',
		reason:
			'The list of client identities permitted to administer this instance. Withheld with the writes below: naming them tells an agent which identity to impersonate. Read it in the console.'
	},
	{
		method: 'POST',
		path: '/admin/api/mcp/clients',
		absence: 'withheld',
		reason:
			'Permitting a client identity to administer this instance is a grant of administrative access, and an agent granting one to another agent is a privilege-escalation path. A super administrator does this in the console.'
	},
	{
		method: 'PATCH',
		path: '/admin/api/mcp/clients/:entryId',
		absence: 'withheld',
		reason:
			'Relaxing or tightening the key-proof requirement on a permitted identity changes who may administer this instance. Console-only, with the permit and withdraw operations beside it.'
	},
	{
		method: 'DELETE',
		path: '/admin/api/mcp/clients/:entryId',
		absence: 'withheld',
		reason:
			'Withdrawing a permitted identity is how an operator revokes administrative access — including, potentially, the agent making the call. Console-only.'
	},
	{
		method: 'POST',
		path: '/admin/api/setup',
		absence: 'inapplicable',
		reason:
			'First-run setup runs when no administrator exists yet, so there is nobody who could authorize an agent to perform it. Console-only.'
	},
	{
		method: 'POST',
		path: '/admin/api/invitations/accept',
		absence: 'inapplicable',
		reason:
			'Unauthenticated, and completed by the invited person following a link in their own mail. There is no agent principal to accept as — the same reason first-run setup is inapplicable.'
	},
	{
		method: 'POST',
		path: '/admin/api/logout',
		absence: 'inapplicable',
		reason:
			'Ends a browser session, which an agent connection does not have. Session lifecycle, not a change to a managed entity.'
	},
	{
		method: 'POST',
		path: '/admin/api/me/verification',
		absence: 'inapplicable',
		reason:
			'Mails the signed-in administrator a message that proves their own address. Only the person holding the mailbox can complete it, so an agent has nothing to do with the result. The administrator presses it in the console.'
	},
	{
		method: 'PUT',
		path: '/admin/api/scope',
		absence: 'inapplicable',
		reason:
			'Points a browser console at one of the teams it may administer, and an agent connection has no session to hold that choice. Name the team in each call instead.'
	},
	/*
	 * Trying a sign-in through a provider (specs/088). Not a decision withheld from agents: the try is a
	 * person signing in at the upstream in a browser, and its result is bound to the console session that
	 * started it, which an agent connection does not have.
	 */
	{
		method: 'POST',
		path: '/admin/api/projects/:id/federation/:providerId/try',
		absence: 'inapplicable',
		reason:
			'Trying a sign-in through an identity provider needs a person signing in at that provider in a browser, and its result is shown only to the console session that started it. Do it from the provider page in the admin console.'
	},
	{
		method: 'GET',
		path: '/admin/api/projects/:id/federation/:providerId/try/:tryRef',
		absence: 'inapplicable',
		reason:
			'The result of a sign-in try is readable only by the console session that started it, which an agent connection does not have. Read it on the provider page in the admin console.'
	},
	/*
	 * Since specs/090 a deletion schedules rather than destroys, and is still withheld: thirty days later it
	 * becomes the same destruction, with nobody there to stop it, so consenting to it is consenting to that.
	 * A restore is published (project_restore); it only gives access back.
	 */
	{
		method: 'DELETE',
		path: '/admin/api/projects/:id',
		absence: 'withheld',
		reason:
			'Deleting a project switches off every end-user account in it at once — people, not configuration — and ends, unattended, thirty days later in their destruction, with nothing left afterwards to inspect or restore. In the console an administrator is shown how many, consents to their destruction as a separate act, and types a confirmation word. Withheld by operator decision — delete it in the admin console instead. A project already scheduled for deletion can be brought back with project_restore.'
	},
	{
		method: 'POST',
		path: '/admin/api/projects/:id/purge',
		absence: 'withheld',
		reason:
			'Destroying a project scheduled for deletion, before its date, destroys every end-user account in it — people, not configuration — with nothing left afterwards to inspect or restore. In the console an administrator is shown how many, consents to their destruction as a separate act, and types a confirmation word. Withheld by operator decision — use Delete now in the admin console instead.'
	},
	{
		method: 'DELETE',
		path: '/admin/api/teams/:id',
		absence: 'withheld',
		reason:
			'Deleting a team destroys the owner of whatever it held, and with it the only thing that granted anyone access — the same class as the two container deletions above. Withheld from agents by operator decision; delete it in the admin console instead.'
	},
	/*
	 * Purging recorded faults.
	 *
	 * Withheld outright, like the two container deletions above, and NOT as an operator-configurable
	 * opt-in — which is what the specification asked for. It cannot be: the published operation set is
	 * invariant under capability switches, asserted twice over by
	 * `test/mcp/capability_invariance.spec.ts` (once on the tool list under every flag combination, once
	 * on this module's own source containing no flag read). A conditionally registered tool fails both,
	 * and a tool that reads the flag in its body fails the second by construction.
	 *
	 * So an agent may see what a purge would remove and never perform one. That is a real reduction
	 * against the specification, recorded here rather than in a comment claiming the opt-in exists.
	 */
	{
		method: 'DELETE',
		path: '/admin/api/errors',
		absence: 'withheld',
		reason:
			'Purging recorded faults destroys the only account of what went wrong, and cannot be undone. Withheld from agents — purge them in the admin console instead. Use error_purge_preview to see what a purge would remove.'
	}
];

/* The operations an agent must be told about, in the order the table declares them. */
export const withheldConsoleOperations: readonly ExcludedConsoleOperation[] =
	excludedConsoleOperations.filter((e) => e.absence === 'withheld');

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
		team_delete: '/admin/api/teams/:id',
		project_delete: '/admin/api/projects/:id',
		project_purge: '/admin/api/projects/:id/purge',
		setup_bootstrap: '/admin/api/setup',
		logout: '/admin/api/logout',
		scope_switch: '/admin/api/scope',
		error_purge: '/admin/api/errors',
		federation_provider_try:
			'/admin/api/projects/:id/federation/:providerId/try'
	};
	const path = guesses[name];
	return path
		? excludedConsoleOperations.find((e) => e.path === path)
		: undefined;
}
