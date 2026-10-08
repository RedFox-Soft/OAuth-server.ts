/*
 * The not-found page carries this text in every published language at once (404.astro). Its title
 * and description are only ever read in English: the page is noindex, and the head is one per file.
 */
export default {
	title: 'Page not found — FoxAuth',
	description:
		'There is nothing at this address. The home page and the documentation search are the quickest way back to whatever you were after.',
	heading: 'Page not found.',
	body: 'Either the link is wrong or the page has moved. If you know roughly what you were after, the documentation search will probably get you there faster than guessing at a URL.',
	home: 'Home',
	docs: 'Documentation',
	endpoints: 'Endpoint reference'
};
