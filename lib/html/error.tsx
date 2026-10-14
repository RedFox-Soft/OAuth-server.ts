import { ComponentProps } from 'react';
import { Result } from 'antd';
import { htmlResponse } from './csp.js';
import { esc } from './escape.js';
import { renderEndUserTree } from './theme/dark.js';
import type { Language } from '../i18n/languages.js';
import { Message } from '../i18n/message.js';
import { PAGES_TEXTS } from '../i18n/texts/pages/index.js';

type ResultStatus = ComponentProps<typeof Result>['status'];

/*
 * The illustration used to be `status === 500 ? '500' : '403'`, which drew a not-found — the most
 * common rendered error there is — as an access refusal, sending operators after a permissions
 * problem that did not exist. Anything without dedicated artwork gets the generic error icon rather
 * than borrowing artwork that names a cause which did not occur.
 */
function illustrationFor(status: number): ResultStatus {
	if (status === 404) {
		return '404';
	}
	if (status === 403) {
		return '403';
	}
	if (status >= 500) {
		return '500';
	}
	return 'error';
}

function renderError(
	status: number,
	title: string,
	subTitle: string | undefined,
	reference: string | undefined,
	language: Language
) {
	/*
	 * The reference is rendered as plain text beside the message, and only when the fault was recorded.
	 * It is the whole point of showing a person an error page rather than a status code: they can quote
	 * it to an operator, who resolves it to the one record. It discloses nothing — the identifier is
	 * random and carries no state.
	 *
	 * The error code and its description are protocol text and stay English in every language, so they
	 * say so; only the frame around them is translated.
	 */
	const T = PAGES_TEXTS[language].error;
	const illustration = illustrationFor(status);
	const heading =
		illustration === '404'
			? T.headings.notFound
			: illustration === '403'
				? T.headings.forbidden
				: illustration === '500'
					? T.headings.serverError
					: T.headings.failed;
	const page = renderEndUserTree(
		<Result
			status={illustration}
			title={heading}
			subTitle={
				<>
					{subTitle ? (
						<>
							{T.details}{' '}
							<span lang="en">
								{status} {subTitle}
							</span>
						</>
					) : (
						<span lang="en">{status}</span>
					)}
					{reference ? (
						<>
							{' '}
							<Message
								t={T.reference}
								values={{ reference }}
							/>
						</>
					) : null}
				</>
			}
		/>,
		{ language }
	);

	return `<!DOCTYPE html>
	<html lang="${language}">
		<head>
			<meta charSet="utf-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1" />
			<title lang="en">${esc(title)}</title>
			${page.head}
		</head>
		<body>${page.html}</body>
	</html>`;
}

export function getErrorHtmlResponse(
	status: number,
	error: string,
	message: string | undefined,
	reference?: string,
	language: Language = 'en'
) {
	const html = renderError(status, error, message, reference, language);
	// Without an explicit status the Response defaults to 200, so an HTML-preferring caller was told
	// "OK" for every error the server rendered as a page — including a not-found.
	return htmlResponse(html, { status, language });
}
