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

	/*
	 * WHY the script sits after the form rather than in <head>. It has to run once `document.forms[0]`
	 * exists, and there are only two ways to arrange that: defer it, or put it past the form. Deferring
	 * an inline script means `type="module"`, since `defer` is ignored on one — and a module script is
	 * skipped outright by a user agent that runs scripts but does not implement modules, which
	 * <noscript> does not render for either. That class (HtmlUnit, some embedded webviews) was left
	 * with no way forward at all. Position is what makes the classic type safe here; moving this back
	 * into <head> restores the dead end.
	 */
	const html = `<!DOCTYPE html>
<html><head>
  <title>Submitting Callback</title>
</head><body>${renderToStaticMarkup(form)}<script>${script}</script></body></html>`;

	return htmlResponse(html);
}
