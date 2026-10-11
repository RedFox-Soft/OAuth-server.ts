import { Elysia } from 'elysia';
import {
	adminAuditStore,
	getBucketStore,
	getProvisioningConnectionStore
} from '../../adapters/index.js';
import type { AdminAuditEntry, AdminAuditQuery } from '../../adapters/types.js';
import {
	CONNECTION_ACTOR_PREFIX,
	UPSTREAM_ACTOR_PREFIX
} from '../../consts/admin_audit_routes.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import {
	AUDIT_PAGE_DEFAULT_LIMIT,
	AUDIT_PAGE_MAX_LIMIT
} from '../../helpers/admin_audit_query.js';
import { AuditQuery, ALLOWED_AUDIT_PARAMS } from './schema.js';

/*
 * Checked against the raw URL, not the validated `query` object, and this is not belt-and-braces:
 * Elysia only lifts *declared* keys out of the query string, so an undeclared one never reaches the
 * schema and `additionalProperties: false` cannot refuse it. Measured, not assumed.
 *
 * It matters here more than on most endpoints. A mistyped filter that is silently dropped answers with
 * the *unfiltered* trail — a wrong answer wearing a 200, on the one surface whose whole purpose is to
 * be trusted about what happened.
 */
function assertNoUnknownParams(url: string): void {
	const unknown = [...new URL(url).searchParams.keys()].filter(
		(name) => !ALLOWED_AUDIT_PARAMS.has(name)
	);
	if (unknown.length > 0) {
		/* One unknown parameter is a field the console can mark; several are a refusal of the whole query. */
		throw new AdminError(
			422,
			`unknown query parameter: ${unknown.sort().join(', ')}`,
			unknown.length === 1 ? { field: unknown[0] } : undefined
		);
	}
}

/*
 * What a non-person actor is called now, read when the page is read and never stored (specs/085): a
 * directory's connection by its display name, an upstream provider by its own. The trail keeps the id,
 * which outlives the name; null says the thing the id named is gone, which an investigator needs to know.
 *
 * One read per distinct actor on the page, not per entry: a directory's sync writes runs of entries under
 * one actor. Only actors on entries the caller was already allowed to read are resolved, and each names a
 * connection or provider of a bucket those entries belong to, so the names widen nothing.
 */
async function actorNames(
	entries: readonly AdminAuditEntry[]
): Promise<Map<string, string | null>> {
	const names = new Map<string, string | null>();
	for (const actorId of new Set(entries.map((entry) => entry.actorId))) {
		if (actorId.startsWith(CONNECTION_ACTOR_PREFIX)) {
			const connection = await getProvisioningConnectionStore().find(
				actorId.slice(CONNECTION_ACTOR_PREFIX.length)
			);
			names.set(actorId, connection?.displayName ?? null);
		} else if (actorId.startsWith(UPSTREAM_ACTOR_PREFIX)) {
			/* A bucket id never holds a ':', so the first one after the prefix ends it; the provider id is the rest. */
			const rest = actorId.slice(UPSTREAM_ACTOR_PREFIX.length);
			const split = rest.indexOf(':');
			const bucket =
				split > 0 ? await getBucketStore().find(rest.slice(0, split)) : null;
			const provider = bucket?.federation.find(
				(p) => p.id === rest.slice(split + 1)
			);
			names.set(actorId, provider?.displayName ?? null);
		}
	}
	return names;
}

function parseBound(value: string | undefined, name: string): Date | undefined {
	if (value === undefined || value === '') {
		return undefined;
	}
	const parsed = new Date(value);
	if (Number.isNaN(parsed.getTime())) {
		throw new AdminError(422, `${name} is not a valid date-time`, {
			field: name
		});
	}
	return parsed;
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
	if (value === undefined || value === '') {
		return fallback;
	}
	const parsed = Number(value);
	if (!Number.isFinite(parsed)) {
		return fallback;
	}
	return Math.trunc(parsed);
}

/*
 * The audit trail's read surface: the caller's groups, or the instance for a super administrator; newest
 * first, paged, and each non-person actor named as it is called now.
 *
 * Deliberately read-only: no POST/PUT/PATCH/DELETE is served on this path or below it, because the
 * trail is append-only by construction and an alteration surface would defeat the property it exists
 * to provide. An unrouted method 404s like any unserved path.
 */
export const auditRoutes = new Elysia({ name: 'admin-audit' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/audit',
		async ({ admin, query, request }) => {
			const ctx = assertAuth(admin);
			assertNoUnknownParams(request.url);
			/*
			 * No role gate. A group reads its own history — "who deleted our client" is a question a tenant
			 * must be able to answer without opening a ticket with the operator, which is the whole point of
			 * self-service.
			 *
			 * The restriction is computed here, from the caller's own memberships, and never read from the
			 * query string. It is the tenant boundary of this surface: a caller-supplied group id would be a
			 * request to read somebody else's trail. An administrator in no group gets an empty array, which
			 * selects nothing — the correct answer, and the opposite of what an omitted restriction would do.
			 *
			 * `undefined` for a super administrator means unrestricted, which is the only way instance-wide
			 * entries (settings, keys, administrator accounts) are readable at all: they belong to no group,
			 * so no group restriction can ever match them.
			 */
			const ownerGroupIds = ctx.superAdmin
				? undefined
				: ctx.memberships.map((m) => m.groupId);

			const from = parseBound(query.from, 'from');
			const to = parseBound(query.to, 'to');
			/*
			 * Refused rather than answered: an empty page is indistinguishable from "nothing happened",
			 * which is the one answer an audit trail must never give by accident.
			 */
			if (from && to && from > to) {
				throw new AdminError(
					422,
					'the time window is backwards: from is later than to',
					{ field: 'from' }
				);
			}

			const page = Math.max(parsePositiveInt(query.page, 1), 1);
			const pageSize = Math.min(
				Math.max(parsePositiveInt(query.pageSize, AUDIT_PAGE_DEFAULT_LIMIT), 1),
				AUDIT_PAGE_MAX_LIMIT
			);

			const filters: AdminAuditQuery = {
				...(query.actor === undefined ? {} : { actor: query.actor }),
				...(query.action === undefined ? {} : { action: query.action }),
				...(query.targetType === undefined
					? {}
					: { targetType: query.targetType }),
				...(query.targetId === undefined ? {} : { targetId: query.targetId }),
				...(query.targetScope === undefined
					? {}
					: { targetScope: query.targetScope }),
				...(query.viaSurface === undefined
					? {}
					: { viaSurface: query.viaSurface }),
				...(query.viaClientId === undefined
					? {}
					: { viaClientId: query.viaClientId }),
				...(query.bucket === undefined ? {} : { bucket: query.bucket }),
				...(query.connection === undefined
					? {}
					: { connection: query.connection }),
				...(query.actionPrefix === undefined
					? {}
					: { actionPrefix: query.actionPrefix }),
				...(from === undefined ? {} : { from }),
				...(to === undefined ? {} : { to }),
				...(ownerGroupIds === undefined ? {} : { ownerGroupIds }),
				limit: pageSize,
				offset: (page - 1) * pageSize
			};

			const { entries, total } = await adminAuditStore.list(filters);
			const names = await actorNames(entries);
			// `page`/`pageSize` are echoed as applied, not as submitted, so a clamped request does not
			// leave the caller paging against a size the server never used.
			return {
				entries: entries.map((entry) =>
					names.has(entry.actorId)
						? { ...entry, actorName: names.get(entry.actorId) ?? null }
						: entry
				),
				total,
				page,
				pageSize
			};
		},
		{ query: AuditQuery }
	);
