import { existsSync } from 'node:fs';
import { Type as t, type Static } from '@sinclair/typebox';

import { ApplicationConfig } from '../configs/application.js';
import {
	adapter,
	getBucketStore,
	getProtectedResourceStore,
	getTelemetryStateStore,
	getUserStore
} from '../adapters/index.js';
import { selectBackend } from '../adapters/selectBackend.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { readPeriodForBuckets } from '../activity/read.js';
import { monthOf } from '../activity/periods.js';
import { packageVersion } from '../helpers/package_version.js';
import {
	RANGE_LABELS,
	REPORT_FORMAT,
	REPORTED_SETTINGS,
	type RangeLabel
} from '../consts/telemetry_fields.js';

const Range = t.Union(RANGE_LABELS.map((label) => t.Literal(label)));

/*
 * The wire shape of format 1 (specs/113 contracts/report-payload.md). Typed so the compiler, not review,
 * keeps the builder to the declared fields. `memory` is a storage value only the test suite ever sees: an
 * instance without a datastore never starts reporting (lib/index.ts).
 */
export const UsageReport = t.Object({
	format: t.Literal(REPORT_FORMAT),
	instanceId: t.String(),
	foxauth: t.Object({ version: t.Optional(t.String()) }),
	runtime: t.Object({
		bun: t.String(),
		os: t.String(),
		arch: t.String(),
		container: t.Boolean()
	}),
	storage: t.Union([
		t.Literal('mongodb'),
		t.Literal('postgres'),
		t.Literal('memory')
	]),
	features: t.Record(t.String(), t.Boolean()),
	size: t.Object({
		projects: Range,
		applications: Range,
		apis: Range,
		administrators: Range,
		monthlyActiveUsers: Range
	}),
	day: t.Optional(
		t.Object({
			date: t.String(),
			tokens: t.Record(t.String(), Range),
			serverErrors: Range
		})
	)
});
export type UsageReport = Static<typeof UsageReport>;

const BOUNDS: readonly [number, RangeLabel][] = [
	[0, '0'],
	[1, '1'],
	[10, '2-10'],
	[100, '11-100'],
	[1000, '101-1000'],
	[10000, '1001-10000'],
	[100000, '10001-100000']
];

export function rangeOf(count: number): RangeLabel {
	for (const [upTo, label] of BOUNDS) {
		if (count <= upTo) return label;
	}
	return '100001+';
}

/*
 * A best guess, and documented as one: there is no reliable way to know from inside. Only the marker files
 * Docker and Podman leave; no environment variable is read for it.
 */
function inContainer(): boolean {
	return existsSync('/.dockerenv') || existsSync('/run/.containerenv');
}

function previousDay(at: Date): string {
	return new Date(at.getTime() - 24 * 60 * 60 * 1000)
		.toISOString()
		.slice(0, 10);
}

async function sizeOf(at: Date): Promise<UsageReport['size']> {
	const buckets = await getBucketStore().list();
	let applications = 0;
	for (const bucket of buckets) {
		applications += (
			await adapter('Client').findByIndexed('bucketId', bucket._id)
		).length;
	}
	const apis = (await getProtectedResourceStore().list()).length;
	const administrators = (await getUserStore(ADMIN_BUCKET_ID).tally()).total;

	/*
	 * People are counted per project and summed, as the instance overview does: a person active in two
	 * projects counts twice, which a range does not notice. A project whose figure cannot be read is left
	 * out rather than failing the report; a listing that fails throws, and then there is no report today.
	 */
	const month = await readPeriodForBuckets(
		buckets.map((bucket) => ({
			_id: bucket._id,
			name: bucket.name,
			...(bucket.slug === undefined ? {} : { slug: bucket.slug }),
			createdAt: bucket.createdAt
		})),
		monthOf(at),
		at
	);
	let monthlyActiveUsers = 0;
	for (const figure of month.figures.values()) {
		monthlyActiveUsers += figure?.total ?? 0;
	}

	return {
		projects: rangeOf(buckets.length),
		applications: rangeOf(applications),
		apis: rangeOf(apis),
		administrators: rangeOf(administrators),
		monthlyActiveUsers: rangeOf(monthlyActiveUsers)
	};
}

async function dayFigures(at: Date): Promise<UsageReport['day']> {
	const date = previousDay(at);
	const counts = (await getTelemetryStateStore().read())?.counts?.[date];
	if (!counts) return undefined;
	const tokens: Record<string, RangeLabel> = {};
	for (const [name, count] of Object.entries(counts.tokens ?? {})) {
		if (count > 0) tokens[name] = rangeOf(count);
	}
	return { date, tokens, serverErrors: rangeOf(counts.serverErrors ?? 0) };
}

/*
 * Builds the report for `at`, or null when one of the size figures cannot be read: the receiver refuses a
 * report without all five, so an incomplete one would only be lost (contract, "What the receiver enforces").
 */
export async function buildReport(
	at: Date,
	instanceId: string
): Promise<UsageReport | null> {
	let size: UsageReport['size'];
	try {
		size = await sizeOf(at);
	} catch {
		return null;
	}
	const version = packageVersion();
	const day = await dayFigures(at);
	const config = ApplicationConfig as Record<string, unknown>;
	return {
		format: REPORT_FORMAT,
		instanceId,
		foxauth: version === undefined ? {} : { version },
		runtime: {
			bun: Bun.version,
			os: process.platform,
			arch: process.arch,
			container: inContainer()
		},
		storage: selectBackend(process.env),
		features: Object.fromEntries(
			REPORTED_SETTINGS.map((key) => [key, config[key] === true])
		),
		size,
		...(day === undefined ? {} : { day })
	};
}
