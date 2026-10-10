import { mapValueError, ValidationError } from 'elysia';
import { TransformDecodeCheckError } from '@sinclair/typebox/value';

/*
 * The first schema violation behind a VALIDATION code, if there is one. Elysia reports two kinds under
 * that code: its own ValidationError, and TypeBox's TransformDecodeCheckError when a member fails to
 * decode (a query value that is not the JSON its schema expects), which carries the violation inside.
 *
 * A leaf, so the admin plane can read a validation failure without loading the authorization-error
 * delivery module, which reaches the model graph and the interaction pages.
 *
 * `message` is TypeBox's own wording, which names the rule and never the value. `summary` is Elysia's,
 * which for a value of the wrong type ends with the value itself ("… but found: <value>"), so it is not
 * for anything that is sent back to whoever submitted it.
 */
export function getFirstError(error: unknown):
	| {
			path: string;
			schemaError: unknown;
			summary?: string;
			message: string;
	  }
	| undefined {
	if (error instanceof ValidationError) {
		const first = mapValueError(error.valueError);
		return (
			first && {
				path: first.path,
				schemaError: first.schema.error,
				summary: first.summary,
				message: first.message
			}
		);
	}
	if (error instanceof TransformDecodeCheckError) {
		const { path, schema, message } = error.error;
		return { path, schemaError: schema.error, summary: message, message };
	}
	return undefined;
}
