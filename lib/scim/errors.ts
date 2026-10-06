import { SCIM_ERROR } from '../consts/scim.js';

/*
 * The scimType values RFC 7644 §3.12 defines for a 400, plus the one this server uses for 409. Nothing else
 * is ever sent, so a client's switch on `scimType` sees only values the RFC told it to expect.
 */
export type ScimType =
	| 'invalidFilter'
	| 'tooMany'
	| 'uniqueness'
	| 'mutability'
	| 'invalidSyntax'
	| 'invalidPath'
	| 'noTarget'
	| 'invalidValue'
	| 'invalidVers'
	| 'sensitive';

/*
 * A refusal in SCIM's own shape. The root error handler stands aside for every SCIM route (keyed on the
 * route, lib/shared/authorization_error_handler.ts), so the SCIM plugin renders this and every other error
 * raised beneath it.
 *
 * `detail` names an attribute or a rule, never a value, another tenant's identifier, or anything from
 * storage (IPSIE AL SCIM §8: errors "SHALL NOT leak internal details").
 */
export class ScimError extends Error {
	readonly scimPlane = true;

	constructor(
		readonly status: number,
		readonly scimType: ScimType | undefined,
		readonly detail: string,
		readonly headers: Readonly<Record<string, string>> = {}
	) {
		super(detail);
		this.name = 'ScimError';
	}
}

export function scimErrorBody(error: {
	status: number;
	scimType?: ScimType;
	detail: string;
}): Record<string, unknown> {
	return {
		schemas: [SCIM_ERROR],
		status: String(error.status),
		...(error.scimType ? { scimType: error.scimType } : {}),
		detail: error.detail
	};
}
