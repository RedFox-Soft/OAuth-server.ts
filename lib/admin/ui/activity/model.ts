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

export interface OverviewRowView {
	bucketId: string;
	name: string;
	slug: string | null;
	reserved: 'default' | 'administrators' | null;
	deleted: string | null;
	current: PeriodFigureView | null;
	previous: PeriodFigureView | null;
}

export interface OverviewView {
	month: string;
	previous: string;
	buckets: OverviewRowView[];
}

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

/* A figure as one line of text: the count, and "so far" while it may still grow. */
export function figureText(figure: PeriodFigureView | null): string {
	if (figure === null) return '—';
	return figure.final ? String(figure.total) : `${String(figure.total)} so far`;
}
