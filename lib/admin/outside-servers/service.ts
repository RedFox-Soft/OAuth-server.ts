import {
	getBucketGroupStore,
	getOutsideAuthorizationServerStore
} from '../../adapters/index.js';
import { UniqueValueTaken } from '../../adapters/conflicts.js';
import type {
	OutsideAuthorizationServer,
	OutsideServerRule,
	UserBucket
} from '../../adapters/types.js';
import { outsideServerId } from '../../assertions/outside_server_id.js';
import {
	forgetAssertionUsage,
	outsideServerUsageKey,
	readAssertionUsage
} from '../../assertions/usage.js';
import { issuerFor } from '../../configs/issuer.js';
import { TOKEN_EXCHANGE_GRANT } from '../../consts/assertion_grants.js';
import { MCP_RESOURCE } from '../../mcp/consts.js';
import { tryFindClient } from '../../models/client.js';
import { scimBaseUrl } from '../../provisioning/addresses.js';
import { belongsToProject } from '../project_applications.js';
import { AdminError } from '../auth/rbac.js';

/*
 * The outside authorization servers a project vouches for its people to with ID-JAGs (specs/108 story 2):
 * every rule about what may be connected, in one place the console and an agent both reach through the admin
 * routes. Each write calls `record` after every refusal and before the write, so a refused request leaves no
 * audit entry and an accepted one is recorded before it takes effect.
 */

type Record = () => Promise<unknown>;

export interface OutsideServerInput {
	issuer?: string;
	displayName?: string;
	applications?: { clientId: string; externalClientId?: string }[];
	rules?: {
		appliesTo: 'everyone' | { groups: string[] };
		apis: { identifier: string; scopes: string[] }[];
	}[];
	signInApplication?: string | null;
	includeEmail?: boolean;
}

function refuse(message: string, field?: string): AdminError {
	return new AdminError(422, message, field ? { field } : undefined);
}

/*
 * Safe to vouch to: an https issuer identifier (RFC 8414 §2 — no query, no fragment), and never this project
 * itself (ID-JAG §9.3: an issuer does not honour what it issued), the instance's administrative MCP endpoint
 * or a SCIM endpoint, none of which is an authorization server anyone vouches to.
 */
function assertIssuer(bucket: UserBucket, issuer: string): void {
	const url = URL.parse(issuer);
	if (!url || url.protocol !== 'https:' || url.search || url.hash) {
		throw refuse(
			'issuer must be an https URL with no query and no fragment',
			'issuer'
		);
	}
	const reserved = [issuerFor(bucket), MCP_RESOURCE, scimBaseUrl(bucket)];
	if (reserved.includes(issuer)) {
		throw refuse(
			"issuer cannot be this project, the instance's administrative MCP endpoint or a SCIM endpoint",
			'issuer'
		);
	}
}

async function assertApplications(
	bucket: UserBucket,
	applications: NonNullable<OutsideServerInput['applications']>
): Promise<void> {
	if (applications.length === 0) {
		throw refuse(
			'at least one application must be allowed to ask',
			'applications'
		);
	}
	const seen = new Set<string>();
	for (const { clientId, externalClientId } of applications) {
		if (seen.has(clientId)) {
			throw refuse(`application ${clientId} is listed twice`, 'applications');
		}
		seen.add(clientId);
		const client = (await belongsToProject(bucket, clientId))
			? await tryFindClient(clientId, { administering: true })
			: undefined;
		if (!client) {
			throw refuse(
				`application ${clientId} is not an application of this project`,
				'applications'
			);
		}
		/* ID-JAG §5 and §9.1: confidential only, so the client the ID-JAG is for is the one that asked. */
		if (client.tokenEndpointAuthMethod === 'none') {
			throw refuse(
				`application ${clientId} does not authenticate, so it cannot exchange tokens`,
				'applications'
			);
		}
		if (!client.grantTypes.includes(TOKEN_EXCHANGE_GRANT)) {
			throw refuse(
				`application ${clientId} does not have the token exchange grant`,
				'applications'
			);
		}
		/* A URL client id is one global namespace (ID-JAG §5); any other is known there by another name. */
		if (!clientId.startsWith('https://') && !externalClientId) {
			throw refuse(
				`application ${clientId} needs its client id at the outside server`,
				'applications'
			);
		}
	}
}

async function assertRules(
	bucket: UserBucket,
	rules: NonNullable<OutsideServerInput['rules']>
): Promise<void> {
	if (rules.length === 0) {
		throw refuse('at least one rule must say who may get what', 'rules');
	}
	for (const rule of rules) {
		if (rule.apis.length === 0) {
			throw refuse('a rule must allow at least one MCP server', 'rules');
		}
		for (const { identifier } of rule.apis) {
			const url = URL.parse(identifier);
			if (!url || url.protocol !== 'https:' || url.hash) {
				throw refuse(
					`MCP server ${identifier} must be an https URL with no fragment`,
					'rules'
				);
			}
		}
		if (rule.appliesTo !== 'everyone') {
			if (rule.appliesTo.groups.length === 0) {
				throw refuse('a rule for groups must name at least one', 'rules');
			}
			for (const groupId of rule.appliesTo.groups) {
				const group = await getBucketGroupStore().find(groupId);
				if (!group || group.bucketId !== bucket._id) {
					throw refuse(
						`group ${groupId} is not a group of this project`,
						'rules'
					);
				}
			}
		}
	}
}

async function assertSignInApplication(
	bucket: UserBucket,
	clientId: string | undefined
): Promise<void> {
	if (clientId !== undefined && !(await belongsToProject(bucket, clientId))) {
		throw refuse(
			`application ${clientId} is not an application of this project`,
			'signInApplication'
		);
	}
}

function storedRules(
	rules: NonNullable<OutsideServerInput['rules']>
): OutsideServerRule[] {
	return rules.map((rule) => ({
		appliesTo:
			rule.appliesTo === 'everyone'
				? 'everyone'
				: { groupIds: [...rule.appliesTo.groups] },
		resources: rule.apis.map(({ identifier, scopes }) => ({
			identifier,
			scopes: [...new Set(scopes)]
		}))
	}));
}

export async function loadOutsideServer(
	bucket: UserBucket,
	id: string
): Promise<OutsideAuthorizationServer> {
	const record = await getOutsideAuthorizationServerStore().find(id);
	if (!record || record.bucketId !== bucket._id) {
		throw new AdminError(404, 'outside authorization server not found');
	}
	return record;
}

export async function createOutsideServer(
	bucket: UserBucket,
	input: Required<
		Pick<
			OutsideServerInput,
			'issuer' | 'displayName' | 'applications' | 'rules'
		>
	> &
		OutsideServerInput,
	record: (id: string) => Promise<unknown>
): Promise<OutsideAuthorizationServer> {
	assertIssuer(bucket, input.issuer);
	await assertApplications(bucket, input.applications);
	await assertRules(bucket, input.rules);
	const signInClientId = input.signInApplication ?? undefined;
	await assertSignInApplication(bucket, signInClientId);

	const id = outsideServerId(bucket._id, input.issuer);
	if (await getOutsideAuthorizationServerStore().find(id)) {
		throw new AdminError(
			409,
			'this outside authorization server is already connected'
		);
	}
	await record(id);
	const now = new Date();
	try {
		return await getOutsideAuthorizationServerStore().create({
			_id: id,
			bucketId: bucket._id,
			issuer: input.issuer,
			displayName: input.displayName.trim(),
			clients: input.applications.map(({ clientId, externalClientId }) => ({
				clientId,
				...(externalClientId ? { externalClientId } : {})
			})),
			rules: storedRules(input.rules),
			...(signInClientId ? { signInClientId } : {}),
			includeEmail: input.includeEmail ?? true,
			createdAt: now,
			updatedAt: now
		});
	} catch (error) {
		if (error instanceof UniqueValueTaken) {
			throw new AdminError(
				409,
				'this outside authorization server is already connected'
			);
		}
		throw error;
	}
}

export async function updateOutsideServer(
	bucket: UserBucket,
	id: string,
	input: OutsideServerInput,
	record: Record
): Promise<OutsideAuthorizationServer> {
	const current = await loadOutsideServer(bucket, id);
	if (input.issuer !== undefined && input.issuer !== current.issuer) {
		throw refuse(
			'the outside server cannot be changed; connect the other one instead',
			'issuer'
		);
	}
	if (input.applications !== undefined) {
		await assertApplications(bucket, input.applications);
	}
	if (input.rules !== undefined) await assertRules(bucket, input.rules);
	const signInClientId =
		input.signInApplication === undefined
			? current.signInClientId
			: (input.signInApplication ?? undefined);
	await assertSignInApplication(bucket, signInClientId);

	await record();
	const { signInClientId: _previous, ...rest } = current;
	const next: OutsideAuthorizationServer = {
		...rest,
		...(input.displayName === undefined
			? {}
			: { displayName: input.displayName.trim() }),
		...(input.applications === undefined
			? {}
			: {
					clients: input.applications.map(({ clientId, externalClientId }) => ({
						clientId,
						...(externalClientId ? { externalClientId } : {})
					}))
				}),
		...(input.rules === undefined ? {} : { rules: storedRules(input.rules) }),
		...(signInClientId ? { signInClientId } : {}),
		...(input.includeEmail === undefined
			? {}
			: { includeEmail: input.includeEmail }),
		updatedAt: new Date()
	};
	await getOutsideAuthorizationServerStore().replace(next);
	return next;
}

export async function deleteOutsideServer(
	bucket: UserBucket,
	id: string,
	record: Record
): Promise<void> {
	await loadOutsideServer(bucket, id);
	await record();
	await getOutsideAuthorizationServerStore().destroy(id);
	await forgetAssertionUsage(outsideServerUsageKey(id));
}

/*
 * A connection as the console and an agent read it: in edge words, with each group named by its current name
 * — or `null` for one deleted since, which then matches nobody — and when it last vouched for somebody.
 */
export async function viewOutsideServer(record: OutsideAuthorizationServer) {
	const groupIds = [
		...new Set(
			record.rules.flatMap((rule) =>
				rule.appliesTo === 'everyone' ? [] : rule.appliesTo.groupIds
			)
		)
	];
	const groups = groupIds.length
		? await getBucketGroupStore().findMany(groupIds)
		: [];
	const names = new Map(
		groups
			.filter((group) => group.bucketId === record.bucketId)
			.map((group) => [group._id, group.displayName])
	);
	return {
		id: record._id,
		issuer: record.issuer,
		displayName: record.displayName,
		applications: record.clients,
		rules: record.rules.map((rule) => ({
			appliesTo:
				rule.appliesTo === 'everyone'
					? ('everyone' as const)
					: {
							groups: rule.appliesTo.groupIds.map((id) => ({
								id,
								name: names.get(id) ?? null
							}))
						},
			apis: rule.resources
		})),
		signInApplication: record.signInClientId ?? null,
		includeEmail: record.includeEmail,
		lastUsedAt: await readAssertionUsage(outsideServerUsageKey(record._id)),
		createdAt: record.createdAt,
		updatedAt: record.updatedAt
	};
}
