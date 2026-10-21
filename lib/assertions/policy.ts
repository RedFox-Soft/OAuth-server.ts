import { getOutsideAuthorizationServerStore } from '../adapters/index.js';
import type { OutsideAuthorizationServer } from '../adapters/types.js';
import { groupIdsOfUser } from '../bucket_groups/service.js';
import {
	InvalidRequest,
	InvalidScope,
	InvalidTarget,
	UnauthorizedClient
} from '../helpers/errors.js';
import { outsideServerId } from './outside_server_id.js';

/*
 * What a project vouches for one person to one outside authorization server, through one application
 * (specs/108): the administrator-defined policy ID-JAG §4.3.3 asks the identity provider to evaluate, and
 * MCP enterprise-managed authorization §7.2 illustrates — "users in the 'engineering' group … read-only".
 *
 * Refusals follow RFC 8693 §2.2.2: a target the project will not vouch to is `invalid_target`; scopes that
 * leave nothing are `invalid_scope`; an application the connection does not let ask is `unauthorized_client`.
 */

export interface Vouching {
	connection: OutsideAuthorizationServer;
	/* The application's client id at the outside server: its own when that is a URL (ID-JAG §5). */
	clientIdThere: string;
	resources: string[];
	scopes: string[];
}

function list(value: string | string[] | undefined): string[] {
	if (value === undefined) return [];
	return Array.isArray(value) ? value : [value];
}

export async function vouchingFor(input: {
	bucketId: string;
	audience: string | string[] | undefined;
	clientId: string;
	accountId: string;
	resource: string | string[] | undefined;
	scope: string | undefined;
}): Promise<Vouching> {
	const audiences = list(input.audience);
	if (audiences.length === 0) {
		throw new InvalidRequest('audience is required');
	}
	/* ID-JAG §4.4.1 makes the receiving server accept one audience only; so this issues for one. */
	if (audiences.length > 1) {
		throw new InvalidTarget('only a single audience is supported');
	}
	const [audience] = audiences;

	const connection = await getOutsideAuthorizationServerStore().find(
		outsideServerId(input.bucketId, audience)
	);
	if (!connection || connection.bucketId !== input.bucketId) {
		throw new InvalidTarget(
			'the audience is not an authorization server this project vouches to'
		);
	}

	const allowed = connection.clients.find(
		(entry) => entry.clientId === input.clientId
	);
	if (!allowed) {
		throw new UnauthorizedClient(
			'this application may not ask for identity assertions for that audience'
		);
	}
	const clientIdThere = input.clientId.startsWith('https://')
		? input.clientId
		: allowed.externalClientId;
	/* Configuration refuses an application listed without one; a record written otherwise names nobody there. */
	if (!clientIdThere) {
		throw new UnauthorizedClient(
			'this application has no client id at that authorization server'
		);
	}

	const needsGroups = connection.rules.some(
		(rule) => rule.appliesTo !== 'everyone'
	);
	const groups = new Set(
		needsGroups ? await groupIdsOfUser(input.bucketId, input.accountId) : []
	);
	/* A group deleted since the rule was written matches nobody: its id is a member of no one's groups. */
	const matching = connection.rules.filter(
		(rule) =>
			rule.appliesTo === 'everyone' ||
			rule.appliesTo.groupIds.some((groupId) => groups.has(groupId))
	);
	if (matching.length === 0) {
		throw new InvalidTarget(
			'nothing at that authorization server is allowed for this person'
		);
	}

	const offered = new Map<string, Set<string>>();
	for (const rule of matching) {
		for (const { identifier, scopes } of rule.resources) {
			const known = offered.get(identifier) ?? new Set<string>();
			for (const scope of scopes) known.add(scope);
			offered.set(identifier, known);
		}
	}

	const requested = list(input.resource);
	for (const identifier of requested) {
		if (!offered.has(identifier)) {
			throw new InvalidTarget(
				'the requested resource is not allowed for this person'
			);
		}
	}
	const resources = requested.length ? requested : [...offered.keys()];

	const available = new Set(
		resources.flatMap((identifier) => [...(offered.get(identifier) ?? [])])
	);
	const asked = input.scope?.split(' ').filter(Boolean);
	const scopes = asked
		? asked.filter((scope) => available.has(scope))
		: [...available];
	if (asked && asked.length > 0 && scopes.length === 0) {
		throw new InvalidScope(
			'no requested scope is allowed for this person there',
			input.scope
		);
	}

	return { connection, clientIdThere, resources, scopes };
}
