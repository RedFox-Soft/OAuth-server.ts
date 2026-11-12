import { networkFactsSummary } from '../../network_facts/state.js';
import { apiSignInPreview, type ApiSignInPreview } from './sign_in_preview.js';
import { sameExpect } from '../buckets/sign_in_preview.js';
import { now } from '../../telemetry/clock.js';
import { Elysia } from 'elysia';
import { uriPathParams } from 'lib/plugins/uri_path_params.js';

import {
	getBucketStore,
	getProtectedResourceStore
} from '../../adapters/index.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import type {
	ProtectedResource,
	ToolsTable,
	UserBucket
} from '../../adapters/types.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { canonicalizeResourceIdentifier } from '../../resources/canonical.js';
import {
	validateScopes,
	scopeFailureMessage,
	validateScopeDescriptions,
	scopeDescriptionFailureMessage,
	type ScopeDescriptionInput
} from '../../resources/scopes.js';
import { isMcpResource } from '../../mcp/resource_server.js';
import { SCIM_BASE_PATH } from '../../consts/scim.js';
import { CreateResourceBody, UpdateResourceBody } from './schema.js';
import { whyCannotExchange } from '../../connected_services/eligibility.js';
import { namespaceOf, ROOT_NAMESPACE } from '../../resources/namespace.js';
import { findDeclaredResource } from '../../resources/registry.js';
import { checkVouching } from '../../resources/vouching.js';
import {
	resourceConnection,
	type ResourceConnection
} from '../../resources/connection.js';
import { issuerFor } from '../../configs/issuer.js';
import {
	issuingBucket,
	isWithinDeploymentDomain
} from '../auth/bucketAddress.js';
import { normaliseHost } from '../../consts/request_host.js';
import { ISSUER } from '../../configs/env.js';
import { isUniqueValueTaken } from '../../adapters/conflicts.js';
import { ROOT_DECLARATION_REFUSAL } from './refusals.js';
import { mayDeclareIn } from '../auth/can.js';
import { assertApiRoom } from '../../plans/enforce.js';
import { DEFAULT_BUCKET_ID } from '../consts.js';
import { isAddressable } from '../auth/bucketAddress.js';
import { apiCheckUrlOf } from '../../behind_proxy/api_address.js';
import { checkIdOf } from '../../behind_proxy/check_id.js';
import { lastAddressFlagsOf } from '../../behind_proxy/usage.js';
import { orphanedBy, validateToolsTable } from '../../resources/tools_table.js';
import {
	apiConditionsOf,
	assertConditionsUsable,
	conditionsFrom,
	personConditionWarnings,
	rowConditionsOf,
	timeZoneFrom
} from '../conditions.js';
import type { VouchingStatus } from '../../resources/vouching.js';

/*
 * Declared protected resources: the audiences this server will mint tokens for, each belonging to one
 * bucket for its whole life (specs/099).
 *
 * Authorization is the bucket's — reading needs its read right, changing its edit right, and an outsider is
 * refused identically whether the bucket exists or not. Declaring a resource in a bucket with an address of
 * its own is ordinary work for the administrator who holds the bucket, and nothing about the resource is
 * fetched or judged: the declaration is unique within that bucket's namespace, so it cannot be a claim
 * on anybody else's, and a server on an internal network or not yet deployed is as declarable as any.
 */

/*
 * Canonicalizes a submitted identifier or refuses the request.
 *
 * The reserved check sits here rather than only in the store because the built-in arm of
 * `getResourceServerInfo` claims this server's own MCP audience *before* the store is consulted — so a
 * declaration naming it could never take effect. Refusing at declaration time turns a silently inert
 * record into a stated conflict, which is the difference between an operator learning the rule and an
 * operator filing a bug.
 */
async function canonicalIdentifier(
	input: string,
	trailingSlashSignificant = false
): Promise<string> {
	const result = canonicalizeResourceIdentifier(input, {
		trailingSlashSignificant
	});
	if (!result.ok) {
		throw new AdminError(
			400,
			result.reason === 'fragment'
				? 'a resource identifier must not carry a fragment'
				: 'a resource identifier must be an absolute URI',
			{ field: 'identifier' }
		);
	}
	if (
		isMcpResource(result.identifier) ||
		(await namesOwnScimEndpoint(result.identifier))
	) {
		throw new AdminError(
			409,
			'that identifier names an audience this server serves itself',
			{ field: 'identifier' }
		);
	}
	return result.identifier;
}

/*
 * A bucket's SCIM endpoint is built in (lib/provisioning/token_policy.ts) and held only by that bucket's
 * connections. A declaration of it would never resolve where the built-in arm answers first, and elsewhere it
 * would mint a token every SCIM principal refuses — so it is refused here, where an operator can be told why,
 * rather than accepted as a declaration that silently does nothing. A directory's SCIM server elsewhere is
 * somebody else's resource and may be declared.
 *
 * Matched on every origin this server answers for a project, not only its own: a project with a hostname of
 * its own or a subdomain of the instance serves its SCIM endpoint there, and comparing against ISSUER alone
 * let exactly those declarations through (specs/101 follow-up). A name beneath the instance's host that no
 * project holds is refused at request time, so a declaration of it would be just as inert.
 */
async function namesOwnScimEndpoint(identifier: string): Promise<boolean> {
	const url = new URL(identifier);
	if (
		url.pathname !== SCIM_BASE_PATH &&
		!url.pathname.endsWith(SCIM_BASE_PATH)
	) {
		return false;
	}
	const host = normaliseHost(url.hostname);
	if (host === null) return false;
	return (
		isWithinDeploymentDomain(host) ||
		(await getBucketStore().findByHost(host)) !== null
	);
}

/*
 * The shared root namespace is a super administrator's to write.
 *
 * Every tenant served at the root — the default bucket, or a bucket with no address of its own —
 * shares one issuer and so one namespace, and a resource's own metadata can say it trusts that issuer
 * but not which of those tenants it belongs to. No proof the resource could offer would stop one of
 * them declaring another's server first, so the only rule that closes squatting here is who may write.
 * Edits and removals are held to it too: a tenant that could repoint a declaration it could not have
 * made would have the same reach by another route.
 */
function assertMayWrite(ctx: AdminContext, namespace: string): void {
	if (!mayDeclareIn(ctx, namespace)) {
		throw new AdminError(403, ROOT_DECLARATION_REFUSAL);
	}
}

function acceptedScopes(scopes: string[]): string[] {
	const result = validateScopes(scopes);
	if (!result.ok) {
		throw new AdminError(
			400,
			scopeFailureMessage(result.reason, result.value),
			{
				field: 'scopes'
			}
		);
	}
	return result.scopes;
}

function acceptedScopeDescriptions(
	descriptions: Readonly<Record<string, ScopeDescriptionInput>>,
	scopes: readonly string[]
) {
	const result = validateScopeDescriptions(descriptions, scopes);
	if (!result.ok) {
		throw new AdminError(
			400,
			scopeDescriptionFailureMessage(result.reason, result.value),
			{ field: 'scopeDescriptions' }
		);
	}
	return result.descriptions;
}

/*
 * The descriptions that survive a change to the scope list: those of scopes still recognised. Undefined
 * when nothing was dropped, so an edit that removed no described scope does not rewrite the map.
 */
function prunedDescriptions(
	existing: Readonly<Record<string, ScopeDescriptionInput>> | undefined,
	scopes: readonly string[]
) {
	if (!existing) return undefined;
	const kept = Object.fromEntries(
		Object.entries(existing).filter(([scope]) => scopes.includes(scope))
	);
	return Object.keys(kept).length === Object.keys(existing).length
		? undefined
		: kept;
}

/*
 * Loads a declared resource by the spelling in the path, and refuses one that belongs to a different
 * bucket than the path names.
 *
 * Looked up the way a token request looks it up — the exact spelling, then the slash-free one — so a
 * resource whose trailing slash is significant is reachable here by the spelling it was declared with,
 * which canonicalizing with the default options made impossible.
 *
 * The bucket check matters at the root: every bucket served there shares one namespace, so
 * `/buckets/A/resources/<B's audience>` would otherwise read — and amend — another bucket's declaration
 * through a bucket the caller does legitimately hold. A 404, as for a resource that does not exist, because
 * from this bucket's point of view it genuinely is not there.
 */
async function loadResource(bucket: UserBucket, resourceId: string) {
	// A malformed or reserved spelling is refused the way a write refuses it, before any lookup.
	await canonicalIdentifier(resourceId);
	const resource = await findDeclaredResource(resourceId, namespaceOf(bucket));
	if (resource?.bucketId !== bucket._id) {
		throw new AdminError(404, 'resource not declared in this project');
	}
	return resource;
}

/*
 * The issuer the project's declared resources get their tokens from: the project's own when it has an address, the
 * root's otherwise. `issuerFor` alone would answer `<ISSUER>/<id>` for a project with no address, which no metadata
 * document could ever be asked to name.
 */
async function tokensIssuer(bucket: UserBucket): Promise<string> {
	const namespace = namespaceOf(bucket);
	return namespace === ROOT_NAMESPACE
		? ISSUER
		: issuerFor(await issuingBucket(namespace));
}

/*
 * A declaration as the edge names it (specs/100), with what the API it declares must serve and check (spec 107), or,
 * when the proxy checks its tokens, where the proxy asks and where the project serves its metadata (specs/123).
 */
function resourceView(
	{ bucketId, ...rest }: ProtectedResource,
	issuer: string,
	bucket: UserBucket
): Omit<
	ProtectedResource,
	| 'bucketId'
	| 'checkedBy'
	| 'proxyAddressProvenAt'
	| 'proxyAddressForgedAt'
	| 'requireCode'
	| 'signInEveryMinutes'
> & {
	projectId: string;
	checkedBy: 'server' | 'proxy';
	/* The API's sign-in requirement (specs/130), always stated. */
	requireCode: boolean;
	signInEveryMinutes: number | null;
	connection: ResourceConnection;
	addresses?: ReturnType<typeof addressesOfApi>;
} {
	const {
		proxyAddressProvenAt: _proven,
		proxyAddressForgedAt: _forged,
		...shown
	} = rest;
	return {
		...shown,
		checkedBy: rest.checkedBy ?? 'server',
		requireCode: rest.requireCode === true,
		signInEveryMinutes: rest.signInEveryMinutes ?? null,
		projectId: bucketId,
		...(rest.checkedBy === 'proxy' ? { addresses: addressesOfApi(rest) } : {}),
		connection: resourceConnection(
			rest,
			issuer,
			rest.checkedBy === 'proxy' ? apiCheckUrlOf(bucket, rest.identifier) : null
		)
	};
}

/*
 * What the proxy's checks showed about the addresses it passes (specs/124 research R6), for the API's Connect.
 * An API has no proxy kind of its own, so which recipes support network conditions is the console's to say.
 */
function addressesOfApi(
	api: Pick<
		ProtectedResource,
		'identifier' | 'proxyAddressProvenAt' | 'proxyAddressForgedAt'
	>
) {
	return {
		provenAt: api.proxyAddressProvenAt?.toISOString() ?? null,
		forgedAt: api.proxyAddressForgedAt?.toISOString() ?? null,
		last: lastAddressFlagsOf(`api:${checkIdOf(api.identifier)}`),
		networkConditionsSupported: true,
		/* Whether network facts can be judged now (specs/129 FR-009, FR-028). */
		networkFacts: networkFactsSummary(now().getTime())
	};
}

/*
 * Whether the proxy may check this API's tokens (specs/123 R10). It needs a host to compare with what the proxy
 * reports, so an https address; and its project needs an address of its own, because a check at the root answers
 * for the project served there and nothing else.
 */
function assertProxyCheckable(bucket: UserBucket, identifier: string): void {
	if (!identifier.startsWith('https://')) {
		throw new AdminError(
			400,
			`an API checked by your proxy must be identified by its https address, not ${identifier}`,
			{ field: 'checkedBy' }
		);
	}
	if (bucket._id !== DEFAULT_BUCKET_ID && !isAddressable(bucket)) {
		throw new AdminError(
			400,
			'this project has no address of its own for your proxy to call; give it one first',
			{ field: 'checkedBy' }
		);
	}
}

function acceptedTools(tools: ToolsTable, scopes: readonly string[]) {
	const result = validateToolsTable(tools, scopes);
	if (!result.ok) {
		throw new AdminError(400, result.message, { field: 'tools' });
	}
	return result.tools;
}

type ToolsBody = NonNullable<(typeof UpdateResourceBody)['static']['tools']>;

/* A row as the console and an agent name it, for messages: the name in quotes, anything unprintable spelled out. */
function toolPlace(name: string): string {
	return `the tool ${JSON.stringify(name)}`;
}

/*
 * A tools table as it will be stored, or a refusal (specs/123, specs/124, specs/131 research R3): the rows with their
 * conditions in stored form, the API's own conditions, and the one zone both read their hours in. A row condition, like
 * the API's, is the proxy's to apply, and a client too old to name its tool cannot be held to one, so a table with any
 * row condition refuses such clients.
 */
async function acceptedToolsBody(
	bucket: UserBucket,
	existing: ProtectedResource,
	body: ToolsBody,
	checkedBy: 'server' | 'proxy',
	scopes: readonly string[]
): Promise<{
	tools: ToolsTable;
	warnings?: { machineClients: string[]; pairwiseClients: string[] };
}> {
	const rows: ToolsTable['rows'] = [];
	for (const row of body.rows) {
		const conditions =
			row.conditions === undefined
				? []
				: rowConditionsOf(
						await conditionsFrom(
							bucket,
							row.conditions,
							toolPlace(row.name),
							'tools',
							'api'
						)
					);
		rows.push({
			name: row.name,
			scopes: row.scopes,
			...(conditions.length > 0 ? { conditions } : {})
		});
	}
	const table = acceptedTools(
		{ rows, otherTools: body.otherTools, withoutMethod: body.withoutMethod },
		scopes
	);
	const rowConditions = table.rows.flatMap((row) => row.conditions ?? []);
	const access = body.access;
	/* Conditions at the proxy are the proxy's to apply; on a server-checked API they would decide nothing. */
	if (
		(access?.conditions.length || rowConditions.length > 0) &&
		checkedBy !== 'proxy'
	) {
		throw new AdminError(
			422,
			'access conditions apply only to an API whose tokens your proxy checks',
			{ field: 'tools' }
		);
	}
	if (rowConditions.length > 0 && table.withoutMethod === 'token') {
		throw new AdminError(
			422,
			"an app too old to say which tool it calls can't be held to one tool's conditions; choose to refuse those apps, or remove the tool's conditions",
			{ field: 'tools', code: 'old_clients_with_tool_conditions' }
		);
	}
	const conditions = access
		? await conditionsFrom(
				bucket,
				access.conditions,
				existing.name,
				'tools',
				'api'
			)
		: [];
	const timeZone =
		access?.timeZone === undefined || access.timeZone === null
			? null
			: timeZoneFrom(access.timeZone, 'tools');
	if (
		timeZone === null &&
		[...conditions, ...rowConditions].some((c) => c.kind === 'time')
	) {
		throw new AdminError(
			422,
			'a time condition needs the time zone its hours are read in',
			{ field: 'tools' }
		);
	}
	const proof = {
		provenAt: existing.proxyAddressProvenAt,
		forgedAt: existing.proxyAddressForgedAt
	};
	await assertConditionsUsable(
		bucket,
		existing.tools?.access?.conditions ?? [],
		conditions,
		proof,
		existing.name,
		'tools'
	);
	for (const row of table.rows) {
		await assertConditionsUsable(
			bucket,
			existing.tools?.rows.find((saved) => saved.name === row.name)
				?.conditions ?? [],
			row.conditions ?? [],
			proof,
			toolPlace(row.name),
			'tools'
		);
	}
	/* Kept only when it says something: a condition, or the zone the rows read their hours in. */
	const tools: ToolsTable =
		conditions.length > 0 || timeZone !== null
			? {
					...table,
					access: {
						conditions: apiConditionsOf(conditions),
						...(timeZone === null ? {} : { timeZone })
					}
				}
			: table;
	const aboutPerson = [...conditions, ...rowConditions].some(
		(c) => c.kind === 'group' || c.kind === 'attribute'
	);
	return aboutPerson
		? { tools, warnings: await personConditionWarnings(bucket._id) }
		: { tools };
}

/*
 * The 409 a sign-in requirement answers until it is confirmed with the counts it previewed (specs/130): the protocol of
 * the application's requirement, so the console and an agent consent the same way. Null when the change may go ahead.
 */
function consentRefused(
	preview: ApiSignInPreview | null,
	confirm: boolean | undefined,
	expect: Readonly<Record<string, number | undefined>> | undefined
) {
	if (!preview) return null;
	if (confirm !== true) {
		return { confirmationRequired: true as const, ...preview };
	}
	if (!sameExpect(expect, preview.expect)) {
		return {
			error: 'admin_error' as const,
			message:
				expect === undefined
					? 'confirm with the counts of the preview you reviewed (expect)'
					: 'what this change affects changed since you reviewed it',
			...preview,
			confirmationRequired: true as const
		};
	}
	return null;
}

function scopeOf(bucket: UserBucket, namespace: string) {
	return {
		bucketId: bucket._id,
		ownerGroupId: bucket.ownerGroupId,
		targetScope: namespace
	};
}

export const resourceRoutes = new Elysia({ name: 'admin-resources' })
	.use(resolveAdmin)
	.use(uriPathParams('resourceId'))
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	/*
	 * A bucket's declarations, with the namespace they are unique within: the bucket's own when it has an
	 * address, the root otherwise — shared with every other root-served bucket, which is why only this
	 * bucket's declarations are listed.
	 */
	.get('/admin/api/projects/:id/resources', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForUsers(ctx, params.id);
		const namespace = namespaceOf(bucket);
		const resources = (
			await getProtectedResourceStore().listByBucket(bucket._id)
		).sort((a, b) =>
			a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0
		);
		const issuer = await tokensIssuer(bucket);
		return {
			namespace: namespace === ROOT_NAMESPACE ? 'root' : 'project',
			resources: resources.map((resource) =>
				resourceView(resource, issuer, bucket)
			)
		};
	})
	.post(
		'/admin/api/projects/:id/resources',
		async ({ admin, params, body, set, status }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);

			const identifier = await canonicalIdentifier(
				body.identifier,
				body.trailingSlashSignificant
			);
			const scopes = acceptedScopes(body.scopes);
			const scopeDescriptions =
				body.scopeDescriptions === undefined
					? undefined
					: acceptedScopeDescriptions(body.scopeDescriptions, scopes);
			const namespace = namespaceOf(bucket);
			assertMayWrite(ctx, namespace);
			if (body.checkedBy === 'proxy') assertProxyCheckable(bucket, identifier);

			/*
			 * Checked before the audit write so a refused declaration leaves no entry describing a change
			 * nobody made — and enforced again by the store, which is where it actually holds: namespace and
			 * identifier are the primary key, so a concurrent duplicate is refused by the datastore rather
			 * than by this read.
			 */
			if (await getProtectedResourceStore().find(namespace, identifier)) {
				throw new AdminError(409, 'that identifier is already declared', {
					field: 'identifier'
				});
			}
			await assertApiRoom(ctx, bucket);
			/* Before the audit entry, so nothing is recorded for a change that was only described (specs/130). */
			const refusal = consentRefused(
				await apiSignInPreview(bucket, identifier, undefined, body),
				body.confirm,
				body.expect
			);
			if (refusal) return status(409, refusal);

			await recordAdminAudit(
				ctx,
				'resource.create',
				identifier,
				scopeOf(bucket, namespace)
			);

			try {
				const resource = await getProtectedResourceStore().create({
					namespace,
					identifier,
					bucketId: bucket._id,
					name: body.name,
					scopes,
					...(scopeDescriptions ? { scopeDescriptions } : {}),
					tokenFormat: body.tokenFormat,
					accessTokenTTL: body.accessTokenTTL,
					trailingSlashSignificant: body.trailingSlashSignificant,
					checkedBy: body.checkedBy,
					requireCode: body.requireCode,
					signInEveryMinutes: body.signInEveryMinutes
				});
				set.status = 201;
				return resourceView(resource, await tokensIssuer(bucket), bucket);
			} catch (error) {
				/*
				 * The primary key refused it between the read above and this write. A conflict rather than a
				 * 500: the caller's request was well-formed, and the answer is the same one the read would
				 * have given a moment earlier. Only that refusal — any other failure is a fault, and mapping
				 * it to "already declared" would hide it behind an answer that is not true.
				 */
				if (isUniqueValueTaken(error)) {
					throw new AdminError(409, 'that identifier is already declared', {
						field: 'identifier'
					});
				}
				throw error;
			}
		},
		{ body: CreateResourceBody }
	)
	.get(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			return resourceView(
				await loadResource(bucket, params.resourceId),
				await tokensIssuer(bucket),
				bucket
			);
		}
	)
	/*
	 * Whether the resource's published metadata currently vouches for this declaration — a diagnostic
	 * the console fetches per row after the list has rendered, so a slow or unreachable resource never
	 * holds the list up. Read-only, so not audited, and blocking nothing in any namespace.
	 *
	 * The issuer it must list is the one its tokens carry: the bucket's own when the bucket has an
	 * address, the root's otherwise. `issuerFor` alone would answer `<ISSUER>/<id>` for a bucket with
	 * no address, which no metadata document could ever be asked to name.
	 */
	.get(
		'/admin/api/projects/:id/resources/:resourceId/vouching',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const resource = await loadResource(bucket, params.resourceId);
			const expectedIssuer = await tokensIssuer(bucket);
			/* The project serves this API's metadata itself (specs/123 R5), naming its own issuer: nothing to fetch. */
			if (resource.checkedBy === 'proxy') {
				return {
					status: 'vouched',
					expectedIssuer,
					servedByProject: true
				} satisfies VouchingStatus;
			}
			return checkVouching(resource.identifier, expectedIssuer, {
				trailingSlashSignificant: resource.trailingSlashSignificant
			});
		}
	)
	.patch(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params, body, status }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const namespace = namespaceOf(bucket);
			assertMayWrite(ctx, namespace);
			const existing = await loadResource(bucket, params.resourceId);
			const { identifier } = existing;

			const scopes =
				body.scopes === undefined ? undefined : acceptedScopes(body.scopes);
			const effectiveScopes = scopes ?? existing.scopes;
			const scopeDescriptions =
				body.scopeDescriptions !== undefined
					? acceptedScopeDescriptions(body.scopeDescriptions, effectiveScopes)
					: scopes === undefined
						? undefined
						: prunedDescriptions(existing.scopeDescriptions, effectiveScopes);
			const attributes = Object.keys(body);
			if (scopeDescriptions && !attributes.includes('scopeDescriptions')) {
				attributes.push('scopeDescriptions');
			}
			const { tools, warnings } =
				body.tools === undefined
					? { tools: undefined, warnings: undefined }
					: await acceptedToolsBody(
							bucket,
							existing,
							body.tools,
							body.checkedBy ?? existing.checkedBy ?? 'server',
							effectiveScopes
						);
			if (scopes !== undefined && body.tools === undefined) {
				const orphan = orphanedBy(existing.tools, effectiveScopes);
				if (orphan) {
					throw new AdminError(
						400,
						`the tool ${orphan.tool} needs ${orphan.scope}; change its row in Tools first`,
						{ field: 'scopes' }
					);
				}
			}
			if (body.checkedBy === 'proxy') assertProxyCheckable(bucket, identifier);
			if (typeof body.exchangedBy === 'string') {
				const why = await whyCannotExchange(bucket, body.exchangedBy);
				if (why) throw new AdminError(400, why, { field: 'exchangedBy' });
			}

			/*
			 * Turning a sign-in requirement on, or shortening it, is consented to with the numbers it was previewed with
			 * (specs/130 research R9), after validation and before the audit entry.
			 */
			const refusal = consentRefused(
				await apiSignInPreview(bucket, identifier, existing, body),
				body.confirm,
				body.expect
			);
			if (refusal) return status(409, refusal);

			// After validation: an entry for a request about to be refused as malformed would describe a
			// change nobody attempted.
			await recordAdminAudit(ctx, 'resource.update', identifier, {
				...scopeOf(bucket, namespace),
				attributes,
				...(body.exchangedBy !== undefined
					? { to: body.exchangedBy ?? '' }
					: body.checkedBy !== undefined
						? { to: body.checkedBy }
						: {})
			});

			const {
				tools: _edgeTools,
				confirm: _confirm,
				expect: _expect,
				...unchanged
			} = body;
			const updated = await getProtectedResourceStore().update(
				namespace,
				identifier,
				{
					...unchanged,
					...(scopes === undefined ? {} : { scopes }),
					...(scopeDescriptions === undefined ? {} : { scopeDescriptions }),
					...(tools === undefined ? {} : { tools })
				}
			);
			const view =
				updated && resourceView(updated, await tokensIssuer(bucket), bucket);
			return view && warnings ? { ...view, warnings } : view;
		},
		{ body: UpdateResourceBody }
	)
	.delete(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const namespace = namespaceOf(bucket);
			assertMayWrite(ctx, namespace);
			const { identifier } = await loadResource(bucket, params.resourceId);

			await recordAdminAudit(
				ctx,
				'resource.delete',
				identifier,
				scopeOf(bucket, namespace)
			);

			await getProtectedResourceStore().destroy(namespace, identifier);
			set.status = 204;
			return null;
		}
	);
