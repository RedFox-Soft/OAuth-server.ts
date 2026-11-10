import { describe, expect, it } from 'bun:test';
import { Type as t } from '@sinclair/typebox';

import { BehindProxyApp } from 'lib/adapters/types.ts';
import { documentOf } from 'lib/adapters/documents.ts';
import { MIGRATIONS } from 'lib/consts/migrations.ts';
import { checksumOf, compare } from 'lib/migrations/state.ts';

/*
 * An older release must never ignore a condition it cannot enforce (specs/124 FR-030). Two doors: it refuses to
 * start against a database this release has fenced, and a process of it still running during a rolling deploy cannot
 * read a rule that carries conditions. Pure checks of the declarations and of the schema read, as the release that
 * predates conditions would make them.
 */

/* The rule shapes as the release before conditions declared them (specs/122). */
const PreviousWho = t.Union([
	t.Object({
		kind: t.Literal('groups'),
		groupIds: t.Array(t.String(), { minItems: 1, maxItems: 50 })
	}),
	t.Object({ kind: t.Literal('project') }),
	t.Object({ kind: t.Literal('public'), subtree: t.Boolean() }),
	t.Object({ kind: t.Literal('none') })
]);
const PreviousApp = t.Object({
	_id: t.String(),
	bucketId: t.String(),
	name: t.String(),
	address: t.String(),
	proxyKind: t.String(),
	rules: t.Array(t.Object({ path: t.String(), who: PreviousWho })),
	createdAt: t.Date(),
	updatedAt: t.Date()
});

const stored = {
	_id: 'app-1',
	bucketId: 'acme',
	name: 'Dashboards',
	address: 'https://grafana.example.com',
	proxyKind: 'caddy',
	rules: [
		{
			path: '/',
			who: {
				kind: 'conditional',
				who: { kind: 'project' },
				conditions: [{ kind: 'network', only: ['203.0.113.0/24'], not: [] }]
			}
		}
	],
	createdAt: new Date(),
	updatedAt: new Date()
};

/**
 * @proves A release that predates conditions cannot let through a request a condition refuses: it will not start on
 * a fenced database, and a running process of it fails the read of a conditioned rule instead of dropping it.
 */
describe('an older release against a database with conditions', () => {
	it('refuses to start, because the database is ahead of what it declares', () => {
		const at = MIGRATIONS.findIndex(
			(migration) => migration.id === '2026-11-06-proxy-conditions-fence'
		);
		expect(at).toBeGreaterThan(-1);
		const records = MIGRATIONS.slice(0, at + 1).map((migration) => ({
			id: migration.id,
			appliedAt: new Date(),
			checksum: checksumOf(migration)
		}));

		const older = compare(MIGRATIONS.slice(0, at), records);

		expect(older.status).toBe('ahead');
		expect(older.unknown).toEqual(['2026-11-06-proxy-conditions-fence']);
	});

	it('fails to read a rule with conditions rather than reading past them', () => {
		expect(() => documentOf('behindProxyApps', PreviousApp, stored)).toThrow(
			/does not match its schema/
		);
		expect(
			documentOf('behindProxyApps', BehindProxyApp, stored).rules
		).toHaveLength(1);
	});
});
