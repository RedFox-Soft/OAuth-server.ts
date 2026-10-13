import { Type as t, type Static } from '@sinclair/typebox';
import { adapter } from '../../adapters/index.js';
import { LOGO_MAX_BYTES } from '../../consts/client_logo.js';

/*
 * A client's logo as an administrator uploaded it (specs/094): a PNG, JPEG or WebP image held as a
 * `data:` URL, in an area of its own beside the client record. Nothing a client registers or publishes
 * about itself reaches here — its `logo_uri` is never read — so every logo on a consent page is one an
 * operator chose. Written straight through `adapter('ClientLogo')`, never through a model class, so the
 * schema exists to be introspected.
 */
export const ClientLogoPayload = t.Object({
	clientId: t.String(),
	image: t.String()
});

export type ClientLogoPayload = Static<typeof ClientLogoPayload>;

type ImageType = 'png' | 'jpeg' | 'webp';

export type ParsedLogo =
	{ ok: true; image: string } | { ok: false; reason: 'format' | 'too-large' };

const DATA_URL = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]*={0,2})$/i;

/*
 * Told from the bytes, never from the name or the declared type: SVG is a document that can carry script
 * and references, and a file renamed to .png is whatever its bytes are.
 */
function sniff(bytes: Buffer): ImageType | undefined {
	const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
	if (bytes.length >= 8 && PNG.every((byte, i) => bytes[i] === byte)) {
		return 'png';
	}
	if (
		bytes.length >= 3 &&
		bytes[0] === 0xff &&
		bytes[1] === 0xd8 &&
		bytes[2] === 0xff
	) {
		return 'jpeg';
	}
	if (
		bytes.length >= 12 &&
		bytes.toString('latin1', 0, 4) === 'RIFF' &&
		bytes.toString('latin1', 8, 12) === 'WEBP'
	) {
		return 'webp';
	}
	return undefined;
}

export function parseLogo(value: string): ParsedLogo {
	const match = DATA_URL.exec(value);
	if (!match || match[2].length % 4 !== 0)
		return { ok: false, reason: 'format' };
	const bytes = Buffer.from(match[2], 'base64');
	if (bytes.length > LOGO_MAX_BYTES) return { ok: false, reason: 'too-large' };
	const type = sniff(bytes);
	if (!type || type !== match[1].toLowerCase()) {
		return { ok: false, reason: 'format' };
	}
	return {
		ok: true,
		image: `data:image/${type};base64,${bytes.toString('base64')}`
	};
}

/* A stored logo that no longer passes — a rule tightened since it was uploaded — reads as none. */
export async function readLogo(clientId: string): Promise<string | undefined> {
	const record = await adapter('ClientLogo').find(clientId);
	if (typeof record?.image !== 'string') return undefined;
	const parsed = parseLogo(record.image);
	return parsed.ok ? parsed.image : undefined;
}

export async function hasLogo(clientId: string): Promise<boolean> {
	return Boolean(await adapter('ClientLogo').find(clientId));
}

export async function writeLogo(
	clientId: string,
	image: string
): Promise<void> {
	await adapter('ClientLogo').upsert(clientId, { clientId, image });
}

export async function clearLogo(clientId: string): Promise<void> {
	await adapter('ClientLogo').destroy(clientId);
}
