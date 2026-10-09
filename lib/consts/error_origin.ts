/*
 * What an error record's `origin` holds when the operator set origin capture to `omitted`, as distinct
 * from null, which means there was nothing to see. A string rather than its own type, because the
 * record stores it in the same field as a captured value; so it is named once and compared by name.
 * Import-free, so the admin console can read it without reaching the error store.
 */
export const ORIGIN_NOT_CAPTURED = 'not-captured';
