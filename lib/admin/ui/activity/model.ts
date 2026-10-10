import { changeBetween, type OverviewRow } from '../../../activity/overview.js';

/*
 * What the console shows of a bucket's active users, derived from the activity routes' answers
 * (lib/admin/activity/routes.ts). Kept apart from the components so the one rule a reader depends on — a
 * figure that may still grow is never shown as if it were final — is a function of the answer alone.
 */

export interface PeriodFigureView {
	period: string;
	final: boolean;
	total: number;
	byKind: { local: number; federated: number; renewal: number };
	provisioned: number;
}

export interface BucketActivityView {
	bucketId: string;
	countingSince: string;
	month: PeriodFigureView | null;
	days: PeriodFigureView[];
	months: PeriodFigureView[];
}

/* The overview's shapes are the server's own, declared once (lib/activity/overview.ts). */
export type {
	CustomerRef,
	CustomerSummary,
	OverviewAnswer,
	OverviewRow,
	SharpChange,
	Sum
} from '../../../activity/overview.js';

export interface FigureRow {
	key: string;
	period: string;
	status: 'final' | 'not final';
	total: number;
	local: number;
	upstream: number;
	renewal: number;
	provisioned: number;
}

export function figureRow(figure: PeriodFigureView): FigureRow {
	return {
		key: figure.period,
		period: figure.period,
		status: figure.final ? 'final' : 'not final',
		total: figure.total,
		local: figure.byKind.local,
		upstream: figure.byKind.federated,
		renewal: figure.byKind.renewal,
		provisioned: figure.provisioned
	};
}

/* A figure or a sum as one line of text: the count, and "so far" while it may still grow. */
export function figureText(
	figure: { total: number; final: boolean } | null
): string {
	if (figure === null) return '—';
	return figure.final ? String(figure.total) : `${String(figure.total)} so far`;
}

export interface UsageFilters {
	search: string;
	hideInactive: boolean;
	hideReserved: boolean;
	hideDeleted: boolean;
}

/*
 * The rows the dashboard shows. Every total on the page is recomputed over exactly these (specs/077,
 * FR-009), so a filter changes the totals as much as it changes the list.
 */
export function visibleRows(
	rows: readonly OverviewRow[],
	filters: UsageFilters
): OverviewRow[] {
	const needle = filters.search.trim().toLowerCase();
	return rows.filter(
		(row) =>
			(needle === '' ||
				row.name.toLowerCase().includes(needle) ||
				row.customer.label.toLowerCase().includes(needle)) &&
			!(filters.hideInactive && (row.months[0]?.total ?? 0) === 0) &&
			!(filters.hideReserved && row.reserved !== null) &&
			!(filters.hideDeleted && row.deleted !== null)
	);
}

export function isFiltered(filters: UsageFilters): boolean {
	return (
		filters.search.trim() !== '' ||
		filters.hideInactive ||
		filters.hideReserved ||
		filters.hideDeleted
	);
}

/*
 * The change from the previous month, as the dashboard writes it: "new" when there was no previous figure,
 * nothing while either month may still grow, otherwise the difference and its share.
 */
export function changeText(
	current: { total: number; final: boolean } | null,
	previous: { total: number; final: boolean } | null
): string {
	if (current === null) return '';
	if (previous === null) return 'new';
	const change = changeBetween(current, previous);
	if (change === null) return '';
	const sign = change.absolute > 0 ? '+' : '';
	return change.percent === null
		? `${sign}${String(change.absolute)}`
		: `${sign}${String(change.absolute)} (${sign}${String(change.percent)} %)`;
}
