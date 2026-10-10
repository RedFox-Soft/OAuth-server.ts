import type { OverviewRow } from '../../../activity/overview.js';

/*
 * The month as a spreadsheet file (specs/077, FR-017), built from the rows the dashboard shows.
 *
 * Bucket and group names are chosen by customers — any administrator can create and name a group — and the
 * file is opened by the operator in a spreadsheet, which runs a cell beginning with `=`, `+`, `-` or `@` as a
 * formula (CSV injection). Such a cell is prefixed with an apostrophe so it is read as text. Tab and carriage
 * return lead the same way in some spreadsheets and are treated alike.
 */

const HEADER = [
	'month',
	'bucket_id',
	'bucket',
	'customer',
	'customer_kind',
	'deleted',
	'reserved',
	'active_users',
	'final',
	'local',
	'upstream',
	'renewal',
	'provisioned',
	'previous_month',
	'previous_active_users',
	'previous_final'
];

const FORMULA_LEAD = /^[=+\-@\t\r]/;

function cell(value: string | number | boolean | null): string {
	/* An absent figure is an empty cell, never 0: zero says nobody was active, absent says nothing was counted. */
	if (value === null) return '""';
	const text = String(value);
	const inert = FORMULA_LEAD.test(text) ? `'${text}` : text;
	return `"${inert.replaceAll('"', '""')}"`;
}

/* A UTF-8 byte-order mark first, so a spreadsheet reads names outside ASCII correctly. */
export function usageCsv(
	month: string,
	previousMonth: string,
	rows: readonly OverviewRow[]
): string {
	const lines = [HEADER.map(cell).join(',')];
	for (const row of rows) {
		const current = row.months[0] ?? null;
		const previous = row.months[1] ?? null;
		lines.push(
			[
				month,
				row.bucketId,
				row.name,
				row.customer.label,
				row.customer.kind,
				row.deleted,
				row.reserved,
				current?.total ?? null,
				current?.final ?? null,
				current?.byKind.local ?? null,
				current?.byKind.federated ?? null,
				current?.byKind.renewal ?? null,
				current?.provisioned ?? null,
				previousMonth,
				previous?.total ?? null,
				previous?.final ?? null
			]
				.map(cell)
				.join(',')
		);
	}
	return `\uFEFF${lines.join('\r\n')}\r\n`;
}
