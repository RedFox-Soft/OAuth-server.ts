import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';

/*
 * There is exactly one route by which a fault becomes an outbound event, asserted over the source.
 *
 * This looks like an odd thing to test until you know what it is defending against. The obvious way
 * to add Sentry to an Elysia server is the official plugin, which hooks the error lifecycle — and
 * that hook fires before the server has settled on a response status, so it reports routine protocol
 * rejections as unhandled faults. The integration therefore reports from one place only: the error
 * store's record continuation, which runs after the fault has already been classified as a defect.
 *
 * A second call site would not fail any other spec in this suite. It would simply start sending
 * events that were never classified, and the first sign of it would be an operator's dashboard full
 * of `invalid_grant`. So the count is pinned here.
 */
/*
 * Separators normalised to '/' because Bun.Glob yields the platform's own: this spec would compare
 * against backslashes on Windows and forward slashes in CI, and pass on exactly one of them.
 */
function sourceFiles(dir: string): string[] {
	return [...new Bun.Glob('**/*.ts').scanSync(dir)].map(
		(f) => `${dir}/${f.replaceAll('\\', '/')}`
	);
}

function callSitesOf(name: string, exclude: string[]): string[] {
	const pattern = new RegExp(`\\b${name}\\s*\\(`);
	return sourceFiles('lib')
		.filter((file) => !exclude.some((e) => file.endsWith(e)))
		.filter((file) => pattern.test(readFileSync(file, 'utf8')));
}

describe('sentry has one dispatch path', () => {
	it('is called from exactly one place, and that place is the error store', () => {
		/* dispatch.ts defines it; event.ts and the specs are not call sites. */
		const callers = callSitesOf('reportFault', ['sentry/dispatch.ts']);
		expect(callers).toEqual(['lib/error_store/capture.ts']);
	});

	/*
	 * The startup path is the one declared exception, and it is exactly one caller too — the boot
	 * entry point. Anything else calling it would be a second unclassified source.
	 */
	it('reports startup failures from exactly one place', () => {
		const callers = callSitesOf('reportStartupFailure', ['sentry/startup.ts']);
		expect(callers).toEqual(['lib/index.ts']);
	});
});
