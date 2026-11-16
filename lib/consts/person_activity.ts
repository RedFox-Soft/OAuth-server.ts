/*
 * The fixed numbers of a person's activity (specs/133). Imports nothing, like the storage inventory, so the console,
 * the stores and the guards can all read it without reaching a datastore module.
 */

/*
 * Kept 90 days after a row was last written, the same on every plan (owner, 2026-11-12): long enough for a quarterly
 * access review and a late-found incident, short enough to stay "strictly necessary" for security.
 */
export const PERSON_ACTIVITY_DAYS = 90;

/*
 * How often each process writes what it holds. A minute is the delay the console announces ("Recorded up to a minute
 * late") and the most a crash loses.
 */
export const PERSON_ACTIVITY_FLUSH_MS = 60_000;

/*
 * Rows per write. Bounded so one PostgreSQL transaction stays short and one MongoDB batch small; a failed chunk loses
 * only itself (specs/133 research R11).
 */
export const PERSON_ACTIVITY_CHUNK = 500;

/*
 * Keys a process holds between two writes, per kind of note and per project (research R10). A successful sign-in is
 * never counted against these: it is rare, costs a password hash, and is the one thing an incident needs. Every other
 * kind is something an outsider can repeat, so a flood of one kind, or in one project, folds into a counted "other"
 * row instead of pushing out another kind or another project.
 */
export const PERSON_ACTIVITY_BUDGETS = {
	signInRefusals: 20_000,
	app: 20_000,
	api: 20_000,
	perProject: 2_000
} as const;

export type PersonActivityBudgets = {
	readonly [K in keyof typeof PERSON_ACTIVITY_BUDGETS]: number;
};

/* The account of a project's overflow row: never an account id, which never contains `*`. */
export const OVERFLOW_ACCOUNT = '*';

/*
 * A tool the request named that is not a row of the API's table. The caller wrote that name, so it is never stored
 * (research R5): only a row name an administrator set, or this.
 */
export const ANOTHER_TOOL = '*another';

/* "New address" is said only once a person has this many earlier successful sign-ins to compare with (У10). */
export const NEW_ADDRESS_AFTER = 5;
