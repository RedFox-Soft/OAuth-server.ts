/*
 * The limits on a client's operator logo (specs/094), declared without imports because the admin body
 * schema needs them and `lib/mcp/catalogue.ts` imports that schema.
 *
 * 64 KiB keeps a crisp 256 px PNG or WebP and keeps the consent page small: the image is embedded in
 * the page, where it appears twice — in the markup and in the hydration props.
 */
export const LOGO_MAX_BYTES = 65_536;

/* 65 536 bytes are 87 384 base64 characters; the rest is room for the longest `data:` prefix. */
export const LOGO_MAX_LENGTH = 87_440;

export const LOGO_FORMAT_MESSAGE = 'logo must be a PNG, JPEG or WebP image';
export const LOGO_SIZE_MESSAGE = 'logo must be at most 64 KiB';
