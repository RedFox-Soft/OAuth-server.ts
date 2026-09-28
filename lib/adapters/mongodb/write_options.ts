/*
 * For a write whose document is built from an object with optional members. The driver's default
 * stores an `undefined` member as BSON null, so an admin session with no refresh token, a bucket with
 * no slug and a federation provider with no signing key were each stored holding nulls their types do
 * not have. This writes them as absent, which is what their writers meant.
 *
 * Never on an operation whose filter could hold an undefined value: the option applies to the filter
 * too, and there it would drop the condition — `{ host: undefined }` would match every document.
 *
 * Its own module rather than beside the client in db.ts, which connects as it loads: a spec that
 * substitutes db.js still runs the stores against this, the real value.
 */
export const ABSENT_UNDEFINED = { ignoreUndefined: true } as const;
