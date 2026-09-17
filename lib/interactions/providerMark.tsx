import type { ReactElement } from 'react';

/*
 * The marks a recognised provider's sign-in button carries, keyed by the catalogue id the login options
 * resolved from the stored issuer.
 *
 * Inline SVG, not a file under `public/` and emphatically not a URL at the provider's CDN. The CDN would
 * make every render of this page — shown to every end user, including everyone who is about to type a
 * password — an outbound request telling that provider somebody is here before they have chosen anything,
 * and it would fail with no network. A local asset would be a binary in a repository that keeps none.
 *
 * Presentation keyed by data, not a branch on a provider's identity: an id that is not in this table simply
 * has no mark, which is the ordinary case for an arbitrary upstream.
 */

/*
 * Google's own mark, unmodified, in its standard four colours — the guidelines allow no monochrome variant
 * and no recolouring, and require it on a light background, which the login card is.
 */
function googleMark(): ReactElement {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 48 48"
			width="18"
			height="18"
			aria-hidden="true"
			focusable="false"
		>
			<path
				fill="#EA4335"
				d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
			/>
			<path
				fill="#4285F4"
				d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
			/>
			<path
				fill="#FBBC05"
				d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
			/>
			<path
				fill="#34A853"
				d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
			/>
		</svg>
	);
}

/*
 * Microsoft's mark is the four-square logo, in its four fixed colours. Their guidance permits no
 * recolouring and no monochrome variant, and requires the squares' proportions be kept.
 */
function microsoftMark(): ReactElement {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 21 21"
			width="18"
			height="18"
			aria-hidden="true"
			focusable="false"
		>
			<path
				fill="#F25022"
				d="M1 1h9v9H1z"
			/>
			<path
				fill="#7FBA00"
				d="M11 1h9v9h-9z"
			/>
			<path
				fill="#00A4EF"
				d="M1 11h9v9H1z"
			/>
			<path
				fill="#FFB900"
				d="M11 11h9v9h-9z"
			/>
		</svg>
	);
}

/*
 * Apple's mark, in black. Their guidelines allow black, white or an outlined variant and nothing else —
 * black on the login card's light background is the combination they specify for it. `currentColor` is
 * deliberately NOT used: it would make the mark follow a theme and stop complying the first time one
 * changed.
 */
function appleMark(): ReactElement {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 17 20"
			width="17"
			height="18"
			aria-hidden="true"
			focusable="false"
		>
			<path
				fill="#000000"
				d="M14.18 10.62c.02 2.5 2.2 3.33 2.22 3.34-.02.05-.35 1.2-1.15 2.38-.7 1.02-1.42 2.03-2.56 2.05-1.12.02-1.48-.66-2.76-.66-1.28 0-1.68.64-2.74.68-1.1.04-1.94-1.1-2.64-2.11C3.1 14.22 2 10.4 3.5 7.82c.74-1.28 2.07-2.09 3.51-2.11 1.08-.02 2.1.73 2.76.73.66 0 1.9-.9 3.2-.77.55.02 2.09.2 3.08 1.5-.08.05-1.84 1.07-1.82 3.2M12.1 4.2c.58-.7.97-1.68.86-2.65-.86.03-1.9.57-2.5 1.27-.54.62-1 1.61-.88 2.56.96.08 1.94-.49 2.52-1.18"
			/>
		</svg>
	);
}

/*
 * GitHub's Invertocat, unmodified, in black. Their usage terms allow black or white and forbid altering
 * the shape; black is the one that reads on a light card.
 */
function githubMark(): ReactElement {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 16 16"
			width="18"
			height="18"
			aria-hidden="true"
			focusable="false"
		>
			<path
				fill="#181717"
				d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.07-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.42 7.42 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A7.995 7.995 0 0 0 16 8c0-4.42-3.58-8-8-8z"
			/>
		</svg>
	);
}

const MARKS: Record<string, () => ReactElement> = {
	google: googleMark,
	microsoft: microsoftMark,
	apple: appleMark,
	github: githubMark
};

export function providerMark(brand: string | undefined): ReactElement | null {
	if (!brand) return null;
	const mark = MARKS[brand];
	return mark ? mark() : null;
}
