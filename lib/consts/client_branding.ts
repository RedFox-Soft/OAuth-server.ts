/*
 * The form an administrator writes a client's primary colour in (specs/106), declared without imports because
 * the admin body schema needs it and `lib/mcp/catalogue.ts` imports that schema.
 *
 * Six hex digits and nothing else. The value ends up in a <style> block on pages that allow inline styles, so
 * this pattern — not a content-security-policy hash — is what keeps a stored value from becoming CSS.
 */
export const PRIMARY_COLOR_PATTERN = /^#[0-9a-f]{6}$/i;

/*
 * The request schema's bound, not the format's: generous, so a value that is merely malformed reaches the
 * service and is refused with the message below rather than with a schema error that names no form.
 */
export const PRIMARY_COLOR_MAX_LENGTH = 32;

export const PRIMARY_COLOR_MESSAGE =
	'primaryColor must be a colour written #rrggbb';
