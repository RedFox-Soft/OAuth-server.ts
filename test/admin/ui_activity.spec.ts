import { describe, it, expect } from 'bun:test';
import fc from 'fast-check';

import {
	figureRow,
	figureText,
	type PeriodFigureView
} from 'lib/admin/ui/activity/model.ts';
import { usageCsv } from 'lib/admin/ui/activity/csv.ts';
import {
	customerSummaries,
	instanceSummary,
	type OverviewRow
} from 'lib/activity/overview.ts';

function figure(final: boolean): PeriodFigureView {
	return {
		period: '2031-03',
		final,
		total: 42,
		byKind: { local: 30, federated: 10, renewal: 20 },
		provisioned: 5
	};
}

/**
 * @proves The console never shows a figure that may still grow as if it were final: the month in progress
 * reads as "so far" and not final, and a closed month reads as its final count.
 */
describe('active users as the console shows them', () => {
	it('marks the month in progress as not final and its count as so far', () => {
		const open = figure(false);

		expect(figureRow(open).status).toBe('not final');
		expect(figureText(open)).toBe('42 so far');
	});

	it('marks a closed month as final with its count', () => {
		const closed = figure(true);

		expect(figureRow(closed).status).toBe('final');
		expect(figureText(closed)).toBe('42');
	});
});

const MONTHS = 3;

const figureArb = fc.option(
	fc.record({
		total: fc.nat(1000),
		local: fc.nat(1000),
		federated: fc.nat(1000),
		renewal: fc.nat(1000),
		provisioned: fc.nat(1000),
		final: fc.boolean()
	}),
	{ nil: null }
);

const rowsArb = fc.array(
	fc.record({
		months: fc.array(figureArb, { minLength: MONTHS, maxLength: MONTHS }),
		group: fc.constantFrom('g1', 'g2', 'g3')
	}),
	{ maxLength: 12 }
);

function rowsOf(
	generated: {
		months: ({
			total: number;
			local: number;
			federated: number;
			renewal: number;
			provisioned: number;
			final: boolean;
		} | null)[];
		group: string;
	}[]
): OverviewRow[] {
	return generated.map((row, i) => {
		const months = row.months.map((figure) =>
			figure === null
				? null
				: {
						period: '2031-03',
						final: figure.final,
						total: figure.total,
						byKind: {
							local: figure.local,
							federated: figure.federated,
							renewal: figure.renewal
						},
						provisioned: figure.provisioned
					}
		);
		return {
			bucketId: `b${String(i)}`,
			name: `bucket ${String(i)}`,
			slug: null,
			reserved: null,
			deleted: null,
			current: months[0] ?? null,
			previous: months[1] ?? null,
			customer: {
				groupId: row.group,
				label: row.group,
				kind: 'regular',
				exists: true
			},
			months,
			days: [],
			previousDays: [],
			unavailable: false
		};
	});
}

/**
 * @proves Every total the usage overview shows is the sum of the bucket figures under it, and a total that
 * includes a figure which may still grow is never shown as final.
 */
describe('totals across buckets', () => {
	it('is the sum of the bucket figures, for every set of figures', () => {
		fc.assert(
			fc.property(rowsArb, (generated) => {
				const rows = rowsOf(generated);
				const instance = instanceSummary(rows, MONTHS, false);
				const customers = customerSummaries(rows, new Map());
				for (let month = 0; month < MONTHS; month += 1) {
					const present = rows.flatMap((row) => row.months[month] ?? []);
					const expected = present.reduce((sum, f) => sum + f.total, 0);
					expect(instance.months[month]?.total ?? 0).toBe(expected);
				}
				for (const customer of customers) {
					const held = rows.filter((row) =>
						customer.bucketIds.includes(row.bucketId)
					);
					const expected = held.reduce(
						(sum, row) => sum + (row.months[0]?.total ?? 0),
						0
					);
					expect(customer.current?.total ?? 0).toBe(expected);
				}
			})
		);
	});

	it('is final only when every figure in it is final, for every set of figures', () => {
		fc.assert(
			fc.property(rowsArb, (generated) => {
				const rows = rowsOf(generated);
				const instance = instanceSummary(rows, MONTHS, false);
				for (let month = 0; month < MONTHS; month += 1) {
					const present = rows.flatMap((row) => row.months[month] ?? []);
					const sum = instance.months[month];
					if (present.length === 0) expect(sum).toBeNull();
					else expect(sum?.final).toBe(present.every((f) => f.final));
				}
			})
		);
	});
});

const BOM = String.fromCharCode(0xfeff);
const CRLF = String.fromCharCode(13, 10);
const TAB = String.fromCharCode(9);
const CR = String.fromCharCode(13);

function exported(rows: OverviewRow[]): string[][] {
	return usageCsv('2031-03', '2031-02', rows)
		.replace(BOM, '')
		.trim()
		.split(CRLF)
		.slice(1)
		.map((line) =>
			line
				.slice(1, -1)
				.split('","')
				.map((cell) => cell.replaceAll('""', '"'))
		);
}

/**
 * @proves A month exported from the usage overview opens in a spreadsheet as data: a name a customer chose
 * cannot run as a formula, and a figure that does not exist is an empty cell, never a zero.
 */
describe('an exported month', () => {
	it('exports a name beginning with a formula character as text', () => {
		const names = ['=1+1', '+1', '-1', '@SUM(A1)', `${TAB}x`, `${CR}x`];
		const rows = rowsOf(
			names.map(() => ({ months: [null, null, null], group: 'g1' }))
		).map((row, i) => ({
			...row,
			name: names[i],
			customer: { ...row.customer, label: names[i] }
		}));

		const cells = exported(rows);

		for (const [i, name] of names.entries()) {
			expect(cells[i][2]).toBe(`'${name}`);
			expect(cells[i][3]).toBe(`'${name}`);
		}
	});

	it('leaves a cell empty, never 0, for a figure that does not exist', () => {
		const [row] = rowsOf([{ months: [null, null, null], group: 'g1' }]);

		const [cells] = exported([row]);

		expect(cells[7]).toBe('');
		expect(cells[14]).toBe('');
	});
});
