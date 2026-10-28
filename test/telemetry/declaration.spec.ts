import { describe, expect, it } from 'bun:test';

import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.ts';
import {
	GRANT_SHORT_NAMES,
	RANGE_LABELS,
	RECEIVER_KEY_SHAPE,
	RECEIVER_MAX_FEATURES,
	RECEIVER_MAX_TOKEN_KEYS,
	REPORT_FORMAT,
	REPORT_MAX_BYTES,
	REPORTED_SETTINGS,
	UNREPORTED_SETTINGS
} from 'lib/consts/telemetry_fields.ts';
import { grantStore } from 'lib/actions/grants/index.ts';

const BOOLEAN_SETTINGS = SETTINGS_CATALOG.filter(
	(setting) => setting.type === 'boolean'
).map((setting): string => setting.key);

const GRANT_NAMES = [...new Set(Object.values(GRANT_SHORT_NAMES))];

/**
 * @proves Every boolean setting is deliberately classified as reported or not, and every key a report
 * can carry is one the receiver accepts, within its counts and the size bound.
 */
describe('the usage report declaration', () => {
	it('classifies every boolean setting as reported, or not reported with a reason', () => {
		for (const key of BOOLEAN_SETTINGS) {
			const reported = REPORTED_SETTINGS.includes(key);
			const unreported = Object.hasOwn(UNREPORTED_SETTINGS, key);
			expect({ key, classified: reported !== unreported }).toEqual({
				key,
				classified: true
			});
			if (unreported) {
				expect(UNREPORTED_SETTINGS[key].length).toBeGreaterThan(10);
			}
		}
	});

	it('names only settings that exist and are boolean', () => {
		for (const key of [
			...REPORTED_SETTINGS,
			...Object.keys(UNREPORTED_SETTINGS)
		]) {
			expect(BOOLEAN_SETTINGS).toContain(key);
		}
	});

	it('gives every grant this server issues through a reported short name', () => {
		for (const grantType of grantStore.keys()) {
			expect(Object.keys(GRANT_SHORT_NAMES)).toContain(grantType);
		}
	});

	it('keeps every reported key within the shape and counts the receiver accepts', () => {
		for (const key of [...REPORTED_SETTINGS, ...GRANT_NAMES]) {
			expect(key).toMatch(RECEIVER_KEY_SHAPE);
		}
		expect(REPORTED_SETTINGS.length).toBeLessThanOrEqual(RECEIVER_MAX_FEATURES);
		expect(GRANT_NAMES.length).toBeLessThanOrEqual(RECEIVER_MAX_TOKEN_KEYS);
	});

	it('keeps a report carrying every declared field at its longest value under the size bound', () => {
		const widest = RANGE_LABELS.reduce((a, b) => (b.length > a.length ? b : a));
		const version = '9'.repeat(32);
		const largest = {
			format: REPORT_FORMAT,
			instanceId: '00000000-0000-4000-8000-000000000000',
			foxauth: { version },
			runtime: {
				bun: version,
				os: 'openbsd',
				arch: 'loong64',
				container: false
			},
			storage: 'postgres',
			features: Object.fromEntries(
				REPORTED_SETTINGS.map((key) => [key, false])
			),
			size: {
				projects: widest,
				applications: widest,
				apis: widest,
				administrators: widest,
				monthlyActiveUsers: widest
			},
			day: {
				date: '2026-12-31',
				tokens: Object.fromEntries(GRANT_NAMES.map((name) => [name, widest])),
				serverErrors: widest
			}
		};

		expect(
			new TextEncoder().encode(JSON.stringify(largest)).byteLength
		).toBeLessThan(REPORT_MAX_BYTES);
	});
});
