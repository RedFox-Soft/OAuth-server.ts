import { ComponentProps } from 'react';
import { Result } from 'antd';
import { htmlResponse } from './csp.js';
import { esc } from './escape.js';
import { renderEndUserTree } from './theme/dark.js';

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
	reference?: string
) {
	/*
	 * The reference is rendered as plain text beside the message, and only when the fault was recorded.
	 * It is the whole point of showing a person an error page rather than a status code: they can quote
	 * it to an operator, who resolves it to the one record. It discloses nothing — the identifier is
	 * random and carries no state.
	 */
	const page = renderEndUserTree(
		<Result
			status={illustrationFor(status)}
			title={status.toString()}
			subTitle={
				reference
					? [subTitle, `(reference: ${reference})`].filter(Boolean).join(' ')
					: subTitle
			}
		/>
	);

	return `<!DOCTYPE html>
	<html>
		<head>
			<meta charSet="utf-8" />
			<meta name="viewport" content="width=device-width, initial-scale=1" />
			<title>${esc(title)}</title>
			${page.head}
		</head>
		<body>${page.html}</body>
	</html>`;
}

export function getErrorHtmlResponse(
	status: number,
	error: string,
	message: string | undefined,
	reference?: string
) {
	const html = renderError(status, error, message, reference);
	// Without an explicit status the Response defaults to 200, so an HTML-preferring caller was told
	// "OK" for every error the server rendered as a page — including a not-found.
	return htmlResponse(html, { status });
}
