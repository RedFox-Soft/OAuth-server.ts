import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

/*
 * The `managedBy` → `ownerGroupId` migration is retired, and this keeps it that way.
 *
 * Deleting it was not the whole job. The migration was the sole writer of a group's `needsReview`
 * flag, and the administrative route could only ever clear that flag — so once the writer went, the
 * field could never again be raised. Left in place it would have been a column that is permanently
 * false, a console section nothing can populate, and a published agent tool describing a state that
 * cannot occur.
 *
 * Dead state of that kind does not announce itself. It reads as a feature to the next author, who
 * then maintains it.
 *
 * The check is on identifiers, not on prose. `managedBy` still appears in several comments that
 * explain why ownership works the way it does now, and that history is worth keeping — what must not
 * come back is code.
 */

const ROOTS = ['lib', 'database'] as const;
const REPO = resolve(import.meta.dir, '../..');

/* Identifiers that must not exist anywhere, in code or comment: nothing refers to them any more, so
 * a mention would mean somebody re-added the thing. */
const GONE = ['needsReview', 'planOwnershipMigration'];

/* Files the migration owned outright. */
const DELETED = [
	'lib/admin/groups/migration.ts',
	'database/verify_migration.ts',
	'test/admin/migration_ownership.spec.ts'
];

function sources(): { shown: string; text: string }[] {
	const found: { shown: string; text: string }[] = [];

	for (const root of ROOTS) {
		const dir = join(REPO, root);
		for (const entry of readdirSync(dir, {
			recursive: true,
			encoding: 'utf8'
		})) {
			if (!entry.endsWith('.ts') && !entry.endsWith('.tsx')) continue;
			const file = join(dir, entry);
			found.push({
				shown: relative(REPO, file).replaceAll('\\', '/'),
				text: readFileSync(file, 'utf8')
			});
		}
	}

	return found;
}

/* Strips line and block comments, so the sweep below sees code rather than the history explaining it. */
function code(text: string): string {
	return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

/**
 * @proves The retired managedBy conversion left no reference behind that could resurrect a code
 * path nothing supports.
 */
describe('the retired ownership migration', () => {
	const files = sources();

	it('reads the tree it claims to, so it cannot pass vacuously', () => {
		expect(files.length).toBeGreaterThan(100);
	});

	for (const identifier of GONE) {
		it(`no retired identifier survives anywhere in the tree`, () => {
			const surviving = files
				.filter((file) => file.text.includes(identifier))
				.map((file) => file.shown);

			expect(surviving).toEqual([]);
		});
	}

	it('leaves managedBy only in prose, never in code', () => {
		// The comments that mention it explain why ownership is a group rather than a manager list, which
		// is the kind of history that stops somebody rebuilding what was removed.
		const inCode = files
			.filter((file) => code(file.text).includes('managedBy'))
			.map((file) => file.shown);

		expect(inCode).toEqual([]);
	});

	it('keeps the files it removed removed', async () => {
		const present: string[] = [];
		for (const path of DELETED) {
			if (await Bun.file(join(REPO, path)).exists()) present.push(path);
		}

		expect(present).toEqual([]);
	});

	it('keeps the reserved unassigned group, which is not residue', async () => {
		// It is how a container nobody owns is reached — a super administrator can create a project with
		// no owner today — so it outlives the migration that first populated it.
		const consts = await Bun.file(join(REPO, 'lib/admin/consts.ts')).text();
		expect(consts).toContain('UNASSIGNED_GROUP_ID');
	});
});
