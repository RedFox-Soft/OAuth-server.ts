import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	ATTACK_REPORT_FIELDS,
	ATTACK_TYPE_NAMES,
	ATTACK_TYPES,
	PROBE_PATHS,
	type ProbeLabel
} from 'lib/consts/attack_report_fields.ts';
import { RECEIVER_KEY_SHAPE } from 'lib/consts/telemetry_fields.ts';
import { buildAttackReport } from 'lib/attack_reports/report.ts';
import type { HourTally } from 'lib/attack_reports/tally.ts';

/*
 * The key paths of a report, with array positions and the type under `counts` written as the declaration
 * writes them, so each path can be looked up in it.
 */
function pathsOf(value: unknown, prefix = ''): string[] {
	if (Array.isArray(value)) {
		// A list of values is one field; a list of objects has fields of its own.
		const objects = value.filter((item) => typeof item === 'object');
		return objects.length > 0
			? objects.flatMap((item) => pathsOf(item, `${prefix}[]`))
			: [prefix];
	}
	if (value !== null && typeof value === 'object') {
		return Object.entries(value).flatMap(([key, item]) => {
			const name = prefix.endsWith('.counts') ? '<type>' : key;
			const path = prefix ? `${prefix}.${name}` : name;
			return prefix.endsWith('.counts') ? [path] : pathsOf(item, path);
		});
	}
	return [prefix];
}

/* A tally in which every type reaches its threshold and every probe label is seen, from IPv4 and IPv6 callers. */
function everyKindOfAttack(): HourTally {
	const counts = Object.fromEntries(
		ATTACK_TYPES.map((type) => [type.name, type.threshold])
	);
	const probes = new Set<ProbeLabel>(PROBE_PATHS.map((probe) => probe.label));
	return {
		addresses: new Map([
			['11.0.0.1', { counts: { ...counts }, probes: new Set(probes) }],
			['2a01:4f8:1:2::/64', { counts: { ...counts }, probes: new Set(probes) }],
			[
				'11.0.0.2',
				{ counts: { probe: 1 }, probes: new Set<ProbeLabel>(['git']) }
			]
		])
	};
}

/**
 * @proves The published declaration is complete: every field, attack type and probe label a report can carry
 * is listed in it, so nothing leaves a server that the public page does not describe, and every name has the
 * shape the receiver accepts.
 */
describe('the attack report declaration', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('lists every field, type and probe label a report can carry', () => {
		const report = buildAttackReport(
			'2026-11-02T10:00:00.000Z',
			everyKindOfAttack(),
			'00000000-0000-4000-8000-000000000000'
		);
		const declared = new Set(ATTACK_REPORT_FIELDS.map((field) => field.path));
		const labels = new Set<string>(PROBE_PATHS.map((probe) => probe.label));
		const types = new Set<string>(ATTACK_TYPE_NAMES);

		expect({
			undeclaredFields: [...new Set(pathsOf(report))].filter(
				(path) => !declared.has(path)
			),
			undeclaredTypes: (report?.addresses ?? [])
				.flatMap((entry) => Object.keys(entry.counts))
				.filter((type) => !types.has(type)),
			undeclaredProbes: (report?.addresses ?? [])
				.flatMap((entry) => entry.probes ?? [])
				.filter((label) => !labels.has(label))
		}).toEqual({
			undeclaredFields: [],
			undeclaredTypes: [],
			undeclaredProbes: []
		});
	});

	it('gives every type name and probe label the shape the receiver accepts', () => {
		const names = [
			...ATTACK_TYPE_NAMES,
			...PROBE_PATHS.map((probe) => probe.label)
		];

		expect(names.filter((name) => !RECEIVER_KEY_SHAPE.test(name))).toEqual([]);
	});
});
