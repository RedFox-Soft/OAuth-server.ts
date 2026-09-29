/*
 * The shortest password an end user may choose, at registration and at a reset. The same eight every
 * password an administrator sets is held to (lib/admin/users-end/schema.ts, the invitation schema). Before
 * this the minimum lived only in the forms' `required` attribute, which a direct POST does not send
 * through, so any string was accepted — and the empty one reached the hash, which refuses it, as a 500.
 */
export const END_USER_PASSWORD_MIN_LENGTH = 8;

export const END_USER_PASSWORD_TOO_SHORT = `Use at least ${END_USER_PASSWORD_MIN_LENGTH} characters.`;
