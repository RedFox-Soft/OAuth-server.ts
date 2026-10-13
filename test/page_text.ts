/*
 * What a reader sees on a rendered page, with the markup taken out. A page wraps names, hosts and codes in
 * elements of their own (<bdi>, <code>), so a sentence a person reads in one piece is several pieces in the
 * HTML, and a substring search over the raw document finds none of them.
 */
export function visible(html: string): string {
	return (
		html
			// Scripts go first, contents and all: the hydration props repeat every label and token, so a
			// count over the whole document measures the props rather than the page.
			.replace(/<script[\s\S]*?<\/script>/g, ' ')
			.replace(/<style[\s\S]*?<\/style>/g, ' ')
			// React's text separators, and the isolation around a name, sit inside one sentence; neither is a
			// gap in it.
			.replace(/<!-- -->/g, '')
			.replace(/<\/?bdi>/g, '')
			.replace(/<[^>]*>/g, ' ')
			.replace(/&#x27;/g, "'")
			.replace(/&quot;/g, '"')
			.replace(/&lt;/g, '<')
			.replace(/&gt;/g, '>')
			.replace(/&amp;/g, '&')
			.replace(/\s+/g, ' ')
			.trim()
	);
}
