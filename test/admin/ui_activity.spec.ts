import { describe, it, expect } from 'bun:test';

import {
	figureRow,
	figureText,
	type PeriodFigureView
} from 'lib/admin/ui/activity/model.ts';

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
