import { Elysia } from 'elysia';

import { errorStore } from '../../adapters/index.js';
import type { ErrorStoreQuery } from '../../adapters/types.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ApplicationConfig } from '../../configs/application.js';
import { droppedCount } from '../../error_store/queue.js';
import { looksLikeReference } from '../../error_store/reference.js';
import { purgeErrors } from './service.js';
import {
	ErrorQuery,
	ErrorSummaryQuery,
	ALLOWED_ERROR_PARAMS,
	ALLOWED_ERROR_SUMMARY_PARAMS
} from './schema.js';

/*
 * Checked against the raw URL, not the validated `query` object: Elysia only lifts *declared* keys out
 * of the query string, so an undeclared one never reaches the schema and `additionalProperties: false`
 * cannot refuse it.
 *
 * It matters more here than on most endpoints, the same way it does on the audit trail: a mistyped
 * filter that is silently dropped answers with the *unfiltered* store — a wrong answer wearing a 200,
 * on a surface whose whole purpose is to be trusted about what failed.
 */
function assertNoUnknownParams(
	url: string,
	allowed: ReadonlySet<string>
): void {
	const unknown = [...new URL(url).searchParams.keys()].filter(
		(name) => !allowed.has(name)
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

function parseInteger(
	value: string | undefined,
	name: string
): number | undefined {
	if (value === undefined || value === '') {
		return undefined;
	}
	const parsed = Number(value);
	if (!Number.isInteger(parsed)) {
		throw new AdminError(422, `${name} must be an integer`);
	}
	return parsed;
}

/*
 * Translates the string-valued query into a store query, and refuses a window that cannot mean
 * anything.
 *
 * A backwards window is refused rather than answered, for the reason the audit trail gives: an empty
 * page is indistinguishable from "nothing failed", which is the one answer a diagnostic surface must
 * never give by accident.
 */
export function toStoreQuery(
	query: Record<string, string | undefined>
): ErrorStoreQuery {
	const from = parseBound(query.from, 'from');
	const to = parseBound(query.to, 'to');
	if (from && to && from > to) {
		throw new AdminError(422, 'from must not be later than to');
	}

	return {
		...(query.errorCode === undefined ? {} : { errorCode: query.errorCode }),
		...(query.route === undefined ? {} : { route: query.route }),
		...(query.surface === undefined ? {} : { surface: query.surface }),
		...(query.status === undefined
			? {}
			: { status: parseInteger(query.status, 'status') }),
		...(query.clientId === undefined ? {} : { clientId: query.clientId }),
		...(query.actor === undefined ? {} : { actor: query.actor }),
		...(from ? { from } : {}),
		...(to ? { to } : {}),
		...(query.limit === undefined
			? {}
			: { limit: parseInteger(query.limit, 'limit') }),
		...(query.offset === undefined
			? {}
			: { offset: parseInteger(query.offset, 'offset') })
	};
}

/*
 * The error store's read surface. Super-admin only, newest first, paged.
 *
 * Read-only for now by construction rather than by policy: a recorded occurrence is immutable, so there
 * is no update to serve. The purge arrives with its own audited route.
 *
 * Deliberately NOT gated on `errorStore.enabled`, though every other capability's endpoints are. The
 * admin operation set is invariant under capability switches — the policy `/admin` carries in
 * lib/consts/route_classification.ts, enforced by test/mcp/capability_invariance.spec.ts — and gating an
 * admin path would additionally split this surface from the agent one, which re-dispatches into these
 * same routes without the gate plugin.
 *
 * The capability is reported in the payload instead. `recording: false` is what keeps "nothing is being
 * recorded" distinguishable from "nothing has failed": an empty page alone would assert the second while
 * meaning the first, which on a diagnostic surface is the one lie that matters.
 */
export const errorRoutes = new Elysia({ name: 'admin-errors' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/errors',
		async ({ admin, query, request }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			assertNoUnknownParams(request.url, ALLOWED_ERROR_PARAMS);

			const page = await errorStore.list(toStoreQuery(query));
			/*
			 * The dropped count is stamped here rather than by the store, which cannot know it: the counter
			 * belongs to the process-local write queue. Non-zero means this page is missing faults that
			 * really happened, and an operator has to be told that rather than left to assume the store is
			 * complete.
			 */
			return {
				...page,
				dropped: droppedCount(),
				recording: ApplicationConfig['errorStore.enabled']
			};
		},
		{ query: ErrorQuery }
	)
	/*
	 * A window only. The filters the listing accepts are refused here rather than ignored: an ignored
	 * filter would answer about the whole store while looking scoped, which on a surface an operator uses
	 * to decide what is wrong is worse than refusing to answer.
	 */
	.get(
		'/admin/api/errors/summary',
		async ({ admin, query, request }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			assertNoUnknownParams(request.url, ALLOWED_ERROR_SUMMARY_PARAMS);

			const summary = await errorStore.summarize(toStoreQuery(query));
			return {
				...summary,
				dropped: droppedCount(),
				recording: ApplicationConfig['errorStore.enabled']
			};
		},
		{ query: ErrorSummaryQuery }
	)
	/*
	 * What a purge with these filters would remove. Reads only, and shares the listing's query schema —
	 * that sharing is what makes the preview provably describe the set the purge will remove, rather than
	 * two parsers agreeing by coincidence.
	 */
	.get(
		'/admin/api/errors/purge-preview',
		async ({ admin, query, request }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			assertNoUnknownParams(request.url, ALLOWED_ERROR_PARAMS);

			return errorStore.previewPurge(toStoreQuery(query));
		},
		{ query: ErrorQuery }
	)
	/*
	 * The one state-changing route here, and the only one that is audited. Its ordering — audit, then
	 * delete — lives in ./service.ts along with the reason.
	 */
	.delete(
		'/admin/api/errors',
		async ({ admin, query, request }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');
			assertNoUnknownParams(request.url, ALLOWED_ERROR_PARAMS);

			return purgeErrors(ctx, toStoreQuery(query));
		},
		{ query: ErrorQuery }
	)
	/*
	 * The lookup an operator reaches for with a reference a caller reported.
	 *
	 * Answers 404 rather than an empty result, because the two are different answers: an empty page would
	 * leave the operator unable to tell a mistyped reference from one whose record has aged out. A
	 * malformed reference is refused before it reaches storage — it cannot be one of ours, so it is not a
	 * query worth making.
	 */
	.get(
		'/admin/api/errors/reference/:reference',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');

			const notFound = () => {
				set.status = 404;
				return adminErrorBody(new AdminError(404, 'no such error record'));
			};

			if (!looksLikeReference(params.reference)) {
				return notFound();
			}
			const hit = await errorStore.findByReference(params.reference);
			return hit ?? notFound();
		}
	)
	/*
	 * Declared after every literal path under `/admin/api/errors`, or `summary` and `purge-preview` are
	 * parsed as group identifiers.
	 */
	.get('/admin/api/errors/:id', async ({ admin, params, set }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');

		const group = await errorStore.get(params.id);
		if (!group) {
			set.status = 404;
			return adminErrorBody(new AdminError(404, 'no such error record'));
		}
		return group;
	});
