import { FRESHNESS_LIMIT_DAYS } from '../../src/data/seo.ts';
import type { PageRecord } from './types.ts';

/*
 * Which claims about other people's products have gone unchecked too long.
 *
 * This deliberately is not a guardrail rule. A build that fails because time passed blocks work on
 * parts of the repository that have nothing to do with the stale page, and the fix a hurried
 * contributor reaches for is to delete the check. So it reports and never fails.
 *
 * A warning alone would satisfy the requirement and none of its intent, because nobody reads build
 * logs. The signal with teeth is the second consumer: the page itself shows a "due for review"
 * notice past the limit, which nobody wants sitting on a page they use to win comparisons — and
 * which tells the reader the truth about the age of the claim in the meantime.
 */

export interface FreshnessEntry {
	route: string;
	competitor: string;
	lastChecked: string;
	ageDays: number;
	stale: boolean;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export function ageInDays(lastChecked: string, now = new Date()): number {
	const then = Date.parse(lastChecked);
	if (Number.isNaN(then)) return Number.POSITIVE_INFINITY;
	return Math.floor((now.getTime() - then) / DAY_MS);
}

export function isStale(lastChecked: string, now = new Date()): boolean {
	return ageInDays(lastChecked, now) > FRESHNESS_LIMIT_DAYS;
}

/*
 * Read from the built pages rather than the content collection, for the same reason every other
 * check here does: the date a reader sees is the one that matters, and it is the one that shipped.
 */
export function freshnessReport(
	pages: PageRecord[],
	now = new Date()
): FreshnessEntry[] {
	const entries: FreshnessEntry[] = [];
	for (const page of pages) {
		if (!page.route.startsWith('/compare/') || page.route === '/compare/')
			continue;
		const match = page.text.match(/Last checked (\d{4}-\d{2}-\d{2})/);
		if (!match) continue;
		const lastChecked = match[1];
		entries.push({
			route: page.route,
			competitor: page.route.replace('/compare/', '').replace('/', ''),
			lastChecked,
			ageDays: ageInDays(lastChecked, now),
			stale: isStale(lastChecked, now)
		});
	}
	return entries.sort((a, b) => b.ageDays - a.ageDays);
}

/** The build's line. Returns undefined when nothing is stale, so a clean build stays quiet. */
export function freshnessWarning(
	entries: FreshnessEntry[]
): string | undefined {
	const stale = entries.filter((entry) => entry.stale);
	if (stale.length === 0) return undefined;

	const lines = stale.map(
		(entry) =>
			`  ${entry.route.padEnd(24)} last checked ${entry.lastChecked} (${entry.ageDays} days)`
	);
	return [
		`seo: ${stale.length} comparison${stale.length === 1 ? '' : 's'} past the ${FRESHNESS_LIMIT_DAYS}-day freshness limit`,
		...lines
	].join('\n');
}
