import { renderToStaticMarkup } from 'react-dom/server';
import { htmlResponse } from './csp.js';

function renderForm(action: string, inputs: Record<string, string>) {
	const formInputs = Object.entries(inputs).map(([key, value]) => (
		<input
			type="hidden"
			name={key}
			value={value}
			key={key}
		/>
	));
	return (
		<form
			method="post"
			action={action}
		>
			{formInputs}
			<noscript>
				Your browser does not support JavaScript or you've disabled it.
				<br />
				<button
					autoFocus
					type="submit"
				>
					Continue
				</button>
			</noscript>
		</form>
	);
}

/*
 * `_ctx` is unused but cannot be dropped: response-mode handlers share one dispatch signature with
 * `query` and `jwt` (see lib/actions/authorization/respond.ts).
 */
export function formPost(
	_ctx: unknown,
	action: string,
	inputs: Record<string, string>
) {
	const form = renderForm(action, inputs);
	const script = `document.forms[0].submit();`;

	const html = `<!DOCTYPE html>
<html><head>
  <title>Submitting Callback</title>
  <script type="module">${script}</script>
</head><body>${renderToStaticMarkup(form)}</body></html>`;

	return htmlResponse(html);
}
