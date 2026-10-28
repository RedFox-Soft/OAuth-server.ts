import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	DISTINCTIVE,
	issueOn,
	passOn,
	receiver,
	seedDistinctiveProject
} from './fixtures.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { REPORT_FIELDS } from 'lib/consts/telemetry_fields.ts';

/* Every leaf path of a JSON value, with `<…>` in place of the keys a field declares as variable. */
function leafPaths(value: unknown, prefix = ''): string[] {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) {
		return [prefix];
	}
	if (prefix === 'features') return ['features.<setting>'];
	if (prefix === 'day.tokens') return ['day.tokens.<grant>'];
	return Object.entries(value).flatMap(([key, member]) =>
		leafPaths(member, prefix ? `${prefix}.${key}` : key)
	);
}

const PUBLISHED = new Set(REPORT_FIELDS.map((field) => field.path));
const ALWAYS = REPORT_FIELDS.filter((field) => !field.absentWhen).map(
	(field) => field.path
);

/**
 * @proves A daily usage report carries exactly the published fields, as ranges, and nothing that names
 * the instance, its projects, its applications or its people.
 */
describe('the daily usage report', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await seedDistinctiveProject();
	});

	it('carries every always-present published field on a default instance', async () => {
		const sent = receiver();
		await passOn('2026-11-02T12:00:00Z');

		expect(sent.bodies).toHaveLength(1);
		const paths = new Set(leafPaths(sent.bodies[0]));
		for (const path of ALWAYS) expect(paths).toContain(path);
	});

	it('carries no field that is not published', async () => {
		const sent = receiver();
		await issueOn('2026-11-03T09:00:00Z', 1);
		await passOn('2026-11-04T12:00:00Z');

		expect(sent.bodies).toHaveLength(1);
		for (const path of leafPaths(sent.bodies[0])) {
			expect(PUBLISHED).toContain(path);
		}
	});

	it("carries none of the instance's issuer, project, application, person or address", async () => {
		const sent = receiver();
		await issueOn('2026-11-05T09:00:00Z', 1);
		await passOn('2026-11-06T12:00:00Z');

		const text = JSON.stringify(sent.bodies);
		for (const secret of [
			ISSUER,
			new URL(ISSUER).host,
			'tele-machine',
			...Object.values(DISTINCTIVE)
		]) {
			expect(text).not.toContain(secret);
		}
	});

	it("reports the tokens issued on a day as that day's range", async () => {
		const sent = receiver();
		await issueOn('2026-11-07T15:00:00Z', 3);
		await passOn('2026-11-08T12:00:00Z');

		expect(sent.bodies.at(-1)).toMatchObject({
			day: { date: '2026-11-07', tokens: { client_credentials: '2-10' } }
		});
	});
});
