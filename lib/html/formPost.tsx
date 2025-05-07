import React from 'react';
import pushInlineSha from '../helpers/script_src_sha.js';
import { renderToStaticMarkup } from 'react-dom/server';

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

export function formPost(ctx, action: string, inputs: Record<string, string>) {
	const form = renderForm(action, inputs);
	const script = `document.forms[0].submit();`;
	//const csp = pushInlineSha(ctx, script);

	const html = `<!DOCTYPE html>
<html><head>
  <title>Submitting Callback</title>
  <script type="module">${script}</script>
</head><body>${renderToStaticMarkup(form)}</body></html>`;

	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8'
		}
	});
}
