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
 * How often each process writes what people used (specs/134 research R2). Use is almost all the volume, and the write
 * rate, and on PostgreSQL the dead row versions, scale with this interval rather than with the roll-up (Н4).
 */
export const PERSON_ACTIVITY_USE_FLUSH_MS = 300_000;

/* Tool names an API use row keeps (research R3): the tools table has no row cap, so the bound is ours. */
export const MAX_TOOLS_PER_ROW = 20;

/* "Refused recently" (research R6): the window, how many rows one read may walk, and how many people it shows. */
export const REFUSALS_WINDOW_MS = 86_400_000;
export const REFUSALS_SCAN = 5_000;
export const REFUSALS_SHOWN = 100;

/* Rows of a person's use one Profile read may walk for "Apps used in the last 90 days" (research R8). */
export const APPS_USED_SCAN = 1_000;

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
	perProject: 2_000,
	/*
	 * What people used has budgets of its own (specs/134 FR-009), so a busy project's use never pushes out a sign-in or
	 * a refusal of any project.
	 */
	use: 40_000,
	perProjectUse: 4_000
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
