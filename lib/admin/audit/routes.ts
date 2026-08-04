import { Elysia, t } from 'elysia';
import { adminAuditStore } from '../../adapters/index.js';
import type { AdminAuditQuery } from '../../adapters/types.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import {
	AUDIT_PAGE_DEFAULT_LIMIT,
	AUDIT_PAGE_MAX_LIMIT
} from '../../helpers/admin_audit_query.js';

/* Everything arrives as a string, since these are query parameters. */
const AuditQuery = t.Object({
	actor: t.Optional(t.String()),
	action: t.Optional(t.String()),
	targetType: t.Optional(t.String()),
	targetId: t.Optional(t.String()),
	targetScope: t.Optional(t.String()),
	from: t.Optional(t.String()),
	to: t.Optional(t.String()),
	page: t.Optional(t.String()),
	pageSize: t.Optional(t.String())
});

const ALLOWED_PARAMS = new Set([
	'actor',
	'action',
	'targetType',
	'targetId',
	'targetScope',
	'from',
	'to',
	'page',
	'pageSize'
]);

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
		(name) => !ALLOWED_PARAMS.has(name)
	);
	if (unknown.length > 0) {
		throw new AdminError(
			422,
			`unknown query parameter: ${unknown.sort().join(', ')}`
		);
	}
}

function parseBound(value: string | undefined, name: string): Date | undefined {
	if (value === undefined || value === '') {
		return undefined;
	}
	const parsed = new Date(value);
	if (Number.isNaN(parsed.getTime())) {
		throw new AdminError(422, `${name} is not a valid date-time`);
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
 * The audit trail's read surface. Super-admin only, newest first, paged.
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
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			assertNoUnknownParams(request.url);

			const from = parseBound(query.from, 'from');
			const to = parseBound(query.to, 'to');
			/*
			 * Refused rather than answered: an empty page is indistinguishable from "nothing happened",
			 * which is the one answer an audit trail must never give by accident.
			 */
			if (from && to && from > to) {
				throw new AdminError(
					422,
					'the time window is backwards: from is later than to'
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
				...(from === undefined ? {} : { from }),
				...(to === undefined ? {} : { to }),
				limit: pageSize,
				offset: (page - 1) * pageSize
			};

			const { entries, total } = await adminAuditStore.list(filters);
			// `page`/`pageSize` are echoed as applied, not as submitted, so a clamped request does not
			// leave the caller paging against a size the server never used.
			return { entries, total, page, pageSize };
		},
		{ query: AuditQuery }
	);
