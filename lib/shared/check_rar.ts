import { isPlainObject } from 'lib/helpers/_/object.js';
import {
	InvalidAuthorizationDetails,
	InvalidRequest,
	OIDCProviderError
} from '../helpers/errors.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

const LIST_FIELDS = ['locations', 'actions', 'datatypes', 'privileges'];
const COMMON_FIELDS = [...LIST_FIELDS, 'identifier'];

/*
 * The parameter legitimately arrives in two shapes and both are its real contract, not a leniency:
 * the query/form parser coerces the JSON string into an array against the declared schema, while PAR
 * stores it parsed and a request object carries it as JSON by construction. Parsing only strings is
 * what made RAR over PAR or a signed request object fail outright.
 */
function readDetails(value: unknown) {
	if (Array.isArray(value)) {
		return value;
	}

	if (typeof value === 'string') {
		try {
			return JSON.parse(value);
		} catch {
			throw new InvalidRequest(
				'could not parse the authorization_details parameter JSON'
			);
		}
	}

	throw new InvalidRequest(
		'authorization_details parameter should be a JSON array'
	);
}

export default async function checkRar(oidc) {
	const { params, client } = oidc;

	if (params.authorization_details !== undefined) {
		if (ApplicationConfig['richAuthorizationRequests.enabled']) {
			// `none` issues no access token, so there is nothing to attach details to. The two
			// neighbouring arms this condition used to carry could never fire: response_type admits
			// only `code` and `none`, so the `token` arm was unreachable and the `code`-absent arm was
			// this same rejection written twice.
			if (params.response_type === 'none') {
				throw new InvalidRequest(
					'authorization_details parameter is not supported for this response_type'
				);
			}

			const details = readDetails(params.authorization_details);

			if (!Array.isArray(details)) {
				throw new InvalidRequest(
					'authorization_details parameter should be a JSON array'
				);
			}

			if (!details.length) {
				params.authorization_details = undefined;
				return;
			}

			let i = 0;
			for (const detail of details) {
				if (!isPlainObject(detail)) {
					throw new InvalidRequest(
						'authorization_details parameter members should be a JSON object'
					);
				}

				if (typeof detail.type !== 'string' || !detail.type.length) {
					throw new InvalidAuthorizationDetails(
						`authorization_details parameter members' type attribute must be a non-empty string (authorization details index ${i})`
					);
				}

				const config =
					ApplicationConfig['richAuthorizationRequests.types'][detail.type];
				if (!config) {
					throw new InvalidAuthorizationDetails(
						`unsupported authorization details type value (authorization details index ${i})`
					);
				}

				/*
				 * The client metadata defaults to [], so every client opts in to each type explicitly
				 * (§10.5). The optional chaining is load-bearing rather than defensive: the metadata is
				 * only recognized while the feature is enabled, so a client registered before it was
				 * turned on has no value at all — and "absent" must mean "no types", not "all types".
				 * The former `=== false` comparison read absent as permitted.
				 */
				if (!client.authorizationDetailsTypes?.includes(detail.type)) {
					throw new InvalidAuthorizationDetails(
						`authorization details type '${detail.type}' is not allowed for this client`
					);
				}

				// check common data fields
				for (const field of LIST_FIELDS) {
					if (
						field in detail &&
						(!Array.isArray(detail[field]) ||
							detail[field].some(
								(value) => typeof value !== 'string' || !value.length
							))
					) {
						throw new InvalidAuthorizationDetails(
							`'${field}' must be an array of non-empty strings (authorization details index ${i})`
						);
					}
				}
				if (
					'identifier' in detail &&
					(typeof detail.identifier !== 'string' || !detail.identifier.length)
				) {
					throw new InvalidAuthorizationDetails(
						`'identifier' must be a non-empty string (authorization details index ${i})`
					);
				}

				checkDescriptor(config, detail, i);

				if (config.validate) {
					try {
						// config.validate is a user-defined RAR type validator expecting a `ctx`-shaped arg
						await config.validate({ oidc }, detail, client);
					} catch (err) {
						// A validator rejection is a §5 type-and-field violation like any other, so it must
						// not surface as a server fault just because the deployment threw a plain Error. One
						// that raises a protocol error deliberately is passed through untouched.
						if (err instanceof OIDCProviderError) {
							throw err;
						}
						throw new InvalidAuthorizationDetails(
							`authorization details type '${detail.type}' was rejected (authorization details index ${i})`
						);
					}
				}

				i++;
			}

			/*
			 * Normalize. Every consumer downstream — the consent prompt, the grant, the shaping seams —
			 * sees one shape, so none of them has to know which delivery path the request arrived by and
			 * none of them parses the parameter a second time.
			 */
			params.authorization_details = details;
		}
	}
}

/*
 * §5: the AS "MUST abort processing and respond with an error invalid_authorization_details" for a
 * known type containing unknown fields, fields with invalid values, and missing required fields. The
 * descriptor is what lets a type declare a closed field set at all.
 */
interface FieldConstraint {
	required?: boolean;
	allowed?: string[];
}

interface TypeDescriptor {
	label: string;
	fields?: Record<string, FieldConstraint>;
	allowUnknownFields?: boolean;
	validate?: (ctx: unknown, detail: unknown, client: unknown) => unknown;
}

function checkDescriptor(
	config: TypeDescriptor,
	detail: Record<string, unknown> & { type: string },
	i: number
) {
	if (!config.allowUnknownFields) {
		for (const field of Object.keys(detail)) {
			if (field !== 'type' && !COMMON_FIELDS.includes(field)) {
				throw new InvalidAuthorizationDetails(
					`'${field}' is not a recognized authorization details field for type '${detail.type}' (authorization details index ${i})`
				);
			}
		}
	}

	const fields = config.fields;
	if (!fields) {
		return;
	}

	for (const [field, constraint] of Object.entries(fields)) {
		if (constraint.required && !(field in detail)) {
			throw new InvalidAuthorizationDetails(
				`'${field}' is required for authorization details type '${detail.type}' (authorization details index ${i})`
			);
		}

		if (!constraint.allowed || !(field in detail)) {
			continue;
		}

		for (const value of detail[field] as string[]) {
			if (!constraint.allowed.includes(value)) {
				throw new InvalidAuthorizationDetails(
					`'${field}' value '${value}' is not allowed for authorization details type '${detail.type}' (authorization details index ${i})`
				);
			}
		}
	}
}
