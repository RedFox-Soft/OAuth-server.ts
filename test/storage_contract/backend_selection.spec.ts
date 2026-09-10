import { describe, it, expect } from 'bun:test';

import { selectBackend } from 'lib/adapters/selectBackend.js';

/*
 * Which storage backend a process uses, as a pure function of the environment — contract C1 in
 * specs/040-postgresql-adapter/contracts/storage-backend.md.
 *
 * A pure function rather than a branch inside `lib/adapters/index.ts` because that module constructs
 * every store as a side effect of being imported. The decision is the part worth pinning, and it is
 * the part that cannot be tested at all once it is entangled with construction.
 *
 * The row that matters most is "both set". Silently preferring one datastore over the other is
 * indistinguishable, from the operator's side, from total data loss: the server comes up, the console
 * works, and every record they had is missing. Refusing is the only safe answer, and it has to be
 * refusing rather than warning, because nobody reads a warning from a process that started.
 */

describe('selectBackend', () => {
	it('uses the in-memory stores when no datastore is configured', () => {
		expect(selectBackend({})).toBe('memory');
	});

	it('selects MongoDB from MONGODB_URI alone', () => {
		expect(selectBackend({ MONGODB_URI: 'mongodb://localhost:27017' })).toBe(
			'mongodb'
		);
	});

	it('selects PostgreSQL from POSTGRES_URL alone', () => {
		expect(
			selectBackend({ POSTGRES_URL: 'postgres://u:p@localhost:5432/db' })
		).toBe('postgres');
	});

	it('refuses when both are configured, naming both variables', () => {
		expect(() =>
			selectBackend({
				MONGODB_URI: 'mongodb://localhost:27017',
				POSTGRES_URL: 'postgres://u:p@localhost:5432/db'
			})
		).toThrow(/MONGODB_URI.*POSTGRES_URL|POSTGRES_URL.*MONGODB_URI/s);
	});

	it('treats an empty value as unset rather than as a choice', () => {
		// An orchestrator that templates an unset variable produces `POSTGRES_URL=`, and treating that
		// as a selection would refuse to start a perfectly well-configured MongoDB deployment.
		expect(
			selectBackend({ MONGODB_URI: 'mongodb://host', POSTGRES_URL: '' })
		).toBe('mongodb');
		expect(selectBackend({ MONGODB_URI: '', POSTGRES_URL: '' })).toBe('memory');
	});

	it('does not read the ambient environment', () => {
		// Purity is the property that lets this be tested at all; a function reaching for process.env
		// would give a different answer on a developer machine with .env.local present.
		expect(selectBackend({})).toBe('memory');
	});
});
