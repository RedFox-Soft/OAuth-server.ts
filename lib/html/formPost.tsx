import { renderToStaticMarkup } from 'react-dom/server';
import { htmlResponse } from './csp.js';
import { esc } from './escape.js';
import { themeHead } from './theme/head.js';
import type { Language } from '../i18n/languages.js';
import { PAGES_TEXTS } from '../i18n/texts/pages/index.js';
import { languageOfContext } from '../i18n/request.js';

function renderForm(
	action: string,
	inputs: Record<string, string>,
	language: Language
) {
	const t = PAGES_TEXTS[language].formPost;
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
				{t.noscript}
				<br />
				<button
					autoFocus
					type="submit"
				>
					{t.continue}
				</button>
			</noscript>
		</form>
	);
}

/*
 * `_oidc` is unused but cannot be dropped: response-mode handlers share one dispatch signature with
 * `query` and `jwt` (see lib/actions/authorization/respond.ts).
 */
/*
 * The parts of a request context this page reads, structurally, so this module stays clear of the model graph:
 * the sign-in's language when there was a sign-in, else the request's own headers (specs/097).
 */
interface LanguageSource {
	entities: { Interaction?: { payload: { language?: Language } } };
	get(name: string): string | undefined;
}

export function formPost(
	oidc: LanguageSource | undefined,
	action: string,
	inputs: Record<string, string>,
	language?: Language
) {
	const lang =
		language ??
		oidc?.entities.Interaction?.payload.language ??
		(oidc ? languageOfContext(oidc).language : 'en');
	const form = renderForm(action, inputs, lang);
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
<html lang="${lang}"><head>
  <title>${esc(PAGES_TEXTS[lang].formPost.title)}</title>
  ${themeHead()}
</head><body>${renderToStaticMarkup(form)}<script>${script}</script></body></html>`;

	return htmlResponse(html, { language: lang });
}
