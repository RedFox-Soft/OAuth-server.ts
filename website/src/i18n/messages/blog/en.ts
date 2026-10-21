import { rich } from '../../types.ts';

export default {
	eyebrow: 'Blog',
	index: {
		heading: 'OAuth in practice',
		description:
			'Notes on OAuth 2.1, OpenID Connect and running your own authorization server, written by the team building FoxAuth as we hit things worth writing down.',
		lead: 'What we learned building an authorization server, written down while it is still fresh. The posts cover protocol decisions, the traps that cost us a day, and the operational questions the reference documentation does not answer.',
		subscribe: (feed: string, guide: string) =>
			rich(
				'Subscribe with ',
				{ link: 'the feed', href: feed },
				', or read the ',
				{ link: 'getting started guide', href: guide },
				' if you would rather try the server than read about it.'
			),
		emptyHeading: 'Nothing published yet',
		emptyBody:
			'The first article is being written. In the meantime the documentation covers how to run the server, and the changelog covers what has shipped.',
		readDocs: 'Read the docs',
		seeShipped: 'See what shipped',
		updated: (date: string) => ` · updated ${date}`
	},
	post: {
		by: 'By',
		updated: ' · updated ',
		storageScope: (backend: string) =>
			`This article covers the ${backend} backend only. The server supports more than one backend, and the others behave differently in places.`,
		agedHeading: 'Worth a second look.',
		aged: (days: number) =>
			` This article was last revised ${days} days ago, and the server has changed since. The behaviour it describes may be out of date. The documentation is current.`,
		allArticles: 'All articles',
		tryIt: 'Try it yourself'
	},
	feed: {
		title: 'FoxAuth blog',
		description:
			'Notes on OAuth 2.1, OpenID Connect and running your own authorization server, written by the team building FoxAuth as we hit things worth writing down.'
	}
};
