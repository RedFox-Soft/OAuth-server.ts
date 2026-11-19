import { ADMIN_BUCKET_ID } from '../admin/consts.js';

/*
 * Whether a project accepts passkeys (specs/139): its setting is on, and it is not the administrators' project, whose
 * people have no account page to add one on (spec D2). Every door, every page and the console's preview ask this,
 * never the field alone.
 *
 * A module of its own, importing one constant, because the console's preview of the sign-in page runs in a browser
 * and reaches it through `signInOptionsOf` (lib/interactions/signInOptions.ts): the rest of the relying-party rules
 * read the instance's address, which a browser bundle must not.
 */
export function passkeysAccepted(bucket: {
	_id: string;
	passkeyLogin?: boolean;
}): boolean {
	return bucket.passkeyLogin === true && bucket._id !== ADMIN_BUCKET_ID;
}
